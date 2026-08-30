from __future__ import annotations

import os
import sys
import argparse
import threading
import time

_DEPS_HINT = """\
Missing Python dependency: {name}

The CLI is a separate package from the backend with its own dependencies.
Install it into the active environment (from the repo root) with one of:

    pip install -e ./cli
    # or
    pip install -r cli/requirements.txt

Then run it again with `python -m cli` (or the `pentest` command)."""

try:
    from dotenv import load_dotenv
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.patch_stdout import patch_stdout

    from cli.api.client import APIClient
    from cli.commands.prompt import handle_prompt
    from cli.commands.slash import SLASH_COMMANDS, execute_command
    from cli.ui.display import print_background_event, print_banner, print_error, print_info
except ModuleNotFoundError as exc:
    if exc.name in {"prompt_toolkit", "httpx", "rich", "dotenv", "pydantic"}:
        print(_DEPS_HINT.format(name=exc.name), file=sys.stderr)
        sys.exit(1)
    raise


class CommandCompleter(Completer):
    """Autocomplete for slash commands."""

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if text.startswith("/"):
            for cmd, (desc, _) in SLASH_COMMANDS.items():
                if cmd.startswith(text):
                    yield Completion(cmd, start_position=-len(text), display_meta=desc)


def _background_event_listener(client: APIClient, stop_event: threading.Event) -> None:
    """Persistent tail of the engagement's one live activity stream — the fix
    for background pipeline / spawned phase-agent work being invisible. Runs
    for the whole interactive session, following whichever engagement is
    currently active (switches when the user's own prompt binds a new one),
    and prints everything the *current* turn's own `send_prompt_stream` isn't
    already showing (tagged `source == "commander"` there — skipped here to
    avoid printing the same tool call twice). "Background" work becomes
    visible the instant it happens, not only when asked about.
    """
    watched: str | None = None
    while not stop_event.is_set():
        eid = client.active_engagement_id
        if not eid:
            time.sleep(1)
            continue
        watched = eid
        try:
            for event_type, data in client.stream_events(eid):
                if stop_event.is_set() or client.active_engagement_id != watched:
                    break
                source = data.get("source", "")
                if source == "commander":
                    continue
                print_background_event(source, event_type, data)
        except Exception:
            pass
        if stop_event.is_set():
            break
        time.sleep(2)


def _prompt_loop(client: APIClient, session) -> None:
    """Read + dispatch loop. ``session`` is a prompt_toolkit session (TTY) or None (piped)."""
    stop_event = threading.Event()
    listener = threading.Thread(
        target=_background_event_listener, args=(client, stop_event), daemon=True
    )
    listener.start()
    try:
        # raw=True is required, not cosmetic: prompt_toolkit's default (False)
        # strips/escapes VT100 sequences before printing, which turns rich's
        # ANSI-styled output (colors, bold) into literal garbage like
        # "?[2;3m" instead of rendering it — raw=True passes escape codes
        # through untouched so the background listener's output interleaves
        # correctly with the interactive prompt without corrupting either.
        with patch_stdout(raw=True):
            _prompt_loop_body(client, session)
    finally:
        stop_event.set()
        client.close()
        print_info("Session ended.")


def _prompt_loop_body(client: APIClient, session) -> None:
    while True:
        if session is not None:
            try:
                user_input = session.prompt("pentest> ", complete_while_typing=True)
            except KeyboardInterrupt:
                continue
            except EOFError:
                break
        else:
            try:
                user_input = input("pentest> ")
            except (EOFError, KeyboardInterrupt):
                break

        text = user_input.strip()
        if not text:
            continue

        try:
            if text.startswith("/"):
                should_continue = execute_command(text, client)
                if not should_continue:
                    break
            else:
                handle_prompt(text, client)
        except KeyboardInterrupt:
            # A running turn (a slow/hung tool call, an open SSE stream) can
            # be interrupted mid-flight — cancel that turn cleanly and return
            # to the prompt instead of dumping a raw traceback from deep
            # inside the HTTP stream.
            print_info("Interrupted.")
            continue


_SCAN_PHASES = ("commander", "recon", "network", "vuln", "web", "exploit", "osint", "full")


def _run_scan_noninteractive(args: argparse.Namespace) -> int:
    """`python -m cli scan --target X [...]` — Executor B's scriptable/CI entry
    point. Binds the target, then drives the conductor the same way the
    interactive `/scan` command does (phase='full' -> the deterministic
    phase_supervisor pipeline; see services/orchestrator.py) — never prompts."""
    from cli.commands.slash import _PHASE_PROMPTS, _bind_engagement, _api_error_text
    from cli.ui.display import consume_agent_stream

    api_url = os.getenv("API_BASE_URL", "http://localhost:9000")
    client = APIClient(base_url=api_url)
    print_info(f"Connected to: {api_url}")

    try:
        health = client.health()
        if health.get("status") != "ok":
            print_error("Backend reported a non-ok health status.")
    except Exception:
        print_error(
            f"Cannot reach the backend at {api_url}. "
            "Start it with `docker compose up -d` (repo root) and try again."
        )
        return 1

    try:
        data = client.compile_engagement_for_target(args.target, force_new=args.force_new)
        _bind_engagement(client, data)
    except Exception as exc:
        print_error(_api_error_text(exc))
        return 1

    if args.engine:
        from cli.commands.slash import _run_engine_scan

        _run_engine_scan(client, args.target, include_low_confidence=args.include_low_confidence)
        client.close()
        return 0

    phase = args.phase
    print_info(f"Scanning {args.target} (phase: {phase}) — the agent will report back when done.")
    stream = client.send_prompt_stream(
        _PHASE_PROMPTS[phase].format(target=args.target),
        engagement_id=client.active_engagement_id,
        phase=phase,
    )
    final = consume_agent_stream(stream)
    client.close()

    if final is None:
        print_error("Agent stream ended without a final response.")
        return 1
    if not final.get("success", True) and final.get("error"):
        print_error(final["error"])
        return 1
    return 0


def main() -> None:
    # Load .env so API_BASE_URL and other env vars are available
    load_dotenv()

    parser = argparse.ArgumentParser(prog="pentest", add_help=False)
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", help="Run a scan non-interactively (scriptable/CI)")
    scan_parser.add_argument("--target", required=True, help="Domain, IP, CIDR, or URL")
    scan_parser.add_argument("--phase", default="full", choices=_SCAN_PHASES)
    scan_parser.add_argument("--engine", action="store_true", help="Autonomous trigger-graph engine, no LLM")
    scan_parser.add_argument("--include-low-confidence", action="store_true")
    scan_parser.add_argument("--force-new", action="store_true", help="Force a new engagement instead of reusing")

    args, _unknown = parser.parse_known_args()
    if args.command == "scan":
        sys.exit(_run_scan_noninteractive(args))

    api_url = os.getenv("API_BASE_URL", "http://localhost:9000")
    client = APIClient(base_url=api_url)

    print_banner()
    print_info(f"Connected to: {api_url}")

    # Warn early when the backend is down so a first-time user knows why commands fail.
    try:
        health = client.health()
        if health.get("status") != "ok":
            print_error("Backend reported a non-ok health status.")
    except Exception:
        print_error(
            f"Cannot reach the backend at {api_url}. "
            "Start it with `docker compose up -d` (repo root) and try again."
        )

    use_tty = sys.stdin is not None and sys.stdin.isatty()
    if use_tty:
        session = PromptSession(
            completer=CommandCompleter(),
            history=InMemoryHistory(),
        )
    else:
        # Piped/non-interactive stdin (CI, scripts): fall back to plain input().
        session = None

    _prompt_loop(client, session)


if __name__ == "__main__":
    main()