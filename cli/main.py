from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from contextlib import nullcontext

from cli.branding import APP_NAME, CLI_COMMAND

_DEPS_HINT = """\
Missing Python dependency: {name}

The CLI is a separate package from the backend with its own dependencies.
Install it into the active environment (from the repo root) with one of:

    pip install -e ./cli
    # or
    pip install -r cli/requirements.txt

Then run it again with `python -m cli` (or the `osprey` command)."""

try:
    from dotenv import load_dotenv
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.shortcuts import CompleteStyle
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.patch_stdout import patch_stdout

    from cli.api.client import APIClient
    from cli.commands.prompt import handle_prompt
    from cli.commands.slash import SLASH_COMMANDS, execute_command
    from cli.ui.display import (
        print_background_event,
        print_banner,
        print_error,
        print_info,
        print_success,
    )
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


def _prompt_message(client: APIClient) -> HTML:
    if client.active_engagement_id:
        short = client.active_engagement_id[:8]
        return HTML(f"<ansigreen><b>{CLI_COMMAND}</b></ansigreen> <ansiblue>{short}</ansiblue> ❯ ")
    return HTML(f"<ansigreen><b>{CLI_COMMAND}</b></ansigreen> ❯ ")


def _bottom_toolbar(client: APIClient) -> HTML:
    engagement = client.active_engagement_id[:8] if client.active_engagement_id else "no engagement"
    return HTML(
        f" <b>{APP_NAME}</b>  api {client.base_url}  session {engagement}  "
        "/help /status /tool N /details "
    )


def _background_event_listener(client: APIClient, stop_event: threading.Event) -> None:
    """Persistent tail of the engagement's one live activity stream — the fix
    for background pipeline / spawned phase-agent work being invisible. Runs
    for the whole interactive session, following whichever engagement is
    currently active (switches when the user's own prompt binds a new one).
    The CLI's own foreground loop (cli/agent/loop.py) renders its own turn
    directly and never publishes onto this stream, so everything shown here
    is genuinely background work. "Background" work becomes visible the
    instant it happens, not only when asked about.
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
                print_background_event(data.get("source", ""), event_type, data)
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
        # patch_stdout only exists to interleave the background listener
        # thread's output correctly with prompt_toolkit's own cursor/prompt-
        # line management — with no PromptSession (piped/non-TTY stdin, the
        # plain input() fallback below), there's nothing of prompt_toolkit's
        # to interleave with, and patch_stdout unconditionally tries to open
        # a real console output handle even then. On Windows that raises
        # NoConsoleScreenBufferError for any piped/CI/redirected run (a
        # narrower terminal reporting itself as xterm-256color without a real
        # Win32 console buffer, e.g. Git Bash/MSYS) — the interactive REPL
        # was simply unusable non-interactively. raw=True (below, when it IS
        # used) is required, not cosmetic: prompt_toolkit's default (False)
        # strips/escapes VT100 sequences before printing, which turns rich's
        # ANSI-styled output (colors, bold) into literal garbage like
        # "?[2;3m" instead of rendering it — raw=True passes escape codes
        # through untouched.
        stdout_ctx = patch_stdout(raw=True) if session is not None else nullcontext()
        with stdout_ctx:
            _prompt_loop_body(client, session)
    finally:
        stop_event.set()
        client.close()
        print_info("Session ended.")


def _prompt_loop_body(client: APIClient, session) -> None:
    while True:
        if session is not None:
            try:
                user_input = session.prompt(
                    _prompt_message(client),
                    complete_while_typing=True,
                    bottom_toolbar=lambda: _bottom_toolbar(client),
                )
            except KeyboardInterrupt:
                continue
            except EOFError:
                break
        else:
            try:
                user_input = input(f"{CLI_COMMAND}> ")
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
    from cli.commands.prompt import handle_prompt
    from cli.commands.slash import _PHASE_PROMPTS, _api_error_text, _bind_engagement

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
        client.close()
        return 1

    target = args.target or args.target_arg
    if not target:
        print_error("Missing target. Usage: osprey scan <target> [--phase full]")
        client.close()
        return 2

    try:
        data = client.compile_engagement_for_target(target, force_new=args.force_new)
        _bind_engagement(client, data)
    except Exception as exc:
        print_error(_api_error_text(exc))
        client.close()
        return 1

    if args.engine:
        from cli.commands.slash import _run_engine_scan

        succeeded = _run_engine_scan(
            client, target, include_low_confidence=args.include_low_confidence
        )
        client.close()
        return 0 if succeeded else 1

    phase = args.phase
    print_info(f"Scanning {target} (phase: {phase}) — the agent will report back when done.")
    succeeded = handle_prompt(_PHASE_PROMPTS[phase].format(target=target), client)
    client.close()
    return 0 if succeeded else 1


def _run_prompt_noninteractive(args: argparse.Namespace) -> int:
    from cli.commands.prompt import handle_prompt
    from cli.commands.slash import _api_error_text

    prompt = " ".join(args.prompt or []).strip()
    if not prompt:
        print_error("Missing prompt. Usage: osprey run \"what should we do next?\"")
        return 2

    api_url = os.getenv("API_BASE_URL", "http://localhost:9000")
    client = APIClient(base_url=api_url)
    if args.target:
        try:
            data = client.compile_engagement_for_target(args.target, force_new=args.force_new)
            client._set_active_engagement(
                data.get("id") or data.get("engagement_id"),
                target=str(data.get("target") or args.target),
            )
        except Exception as exc:
            print_error(_api_error_text(exc))
            client.close()
            return 1

    succeeded = handle_prompt(prompt, client)
    client.close()
    return 0 if succeeded else 1


def _print_scorecard(sc: dict) -> None:
    modes = {
        "false_positive_rate": "deterministic",
        "validated_finding_count": "deterministic",
        "confirmed_without_proof_count": "deterministic",
        "attack_surface_coverage": "deterministic",
        "redundant_action_count": "deterministic",
        "missed_known_vuln_count": "deterministic",
        "time_to_first_validated_finding_seconds": "llm-dependent",
    }
    print_info(f"Scorecard for '{sc['fixture_name']}' (run_id={sc['run_id']}, mode={sc['mode']})")
    for field, mode in modes.items():
        value = sc.get(field)
        shown = "unmeasured" if value is None else value
        print(f"  {field} [{mode}]: {shown}")
    for note in sc.get("notes") or []:
        print_info(f"  note: {note}")


def _run_benchmark_noninteractive(args: argparse.Namespace) -> int:
    """`osprey benchmark record|run|list|diff` — the CLI + CI entry point for
    plans/harness/01-replay-benchmark-harness.md. Never opens the REPL."""
    api_url = os.getenv("API_BASE_URL", "http://localhost:9000")
    client = APIClient(base_url=api_url)
    from cli.commands.slash import _api_error_text

    try:
        if args.benchmark_command == "list":
            data = client.benchmark_list_fixtures()
            fixtures = data.get("fixtures") or []
            if not fixtures:
                print_info("No fixtures yet. Run `osprey benchmark install-builtin` first.")
            for name in fixtures:
                print(f"  {name}")
            return 0

        if args.benchmark_command == "install-builtin":
            data = client.benchmark_install_builtin_fixtures()
            print_success(f"Installed: {', '.join(data.get('installed') or [])}")
            return 0

        if args.benchmark_command == "record":
            if not args.engagement_id or not args.name:
                print_error("Usage: osprey benchmark record --engagement-id ID --name NAME")
                return 2
            data = client.benchmark_record(
                engagement_id=args.engagement_id, name=args.name, target=args.target or ""
            )
            print_success(f"Recorded {data['calls_recorded']} call(s) -> {data['path']}")
            if data.get("degraded_fidelity_calls"):
                print_error(
                    f"{data['degraded_fidelity_calls']} call(s) recorded with degraded fidelity "
                    "(no live Kali artifact reachable) — see backend logs."
                )
            return 0

        if args.benchmark_command == "run":
            if not args.fixture:
                print_error("Usage: osprey benchmark run --fixture NAME")
                return 2
            sc = client.benchmark_run(args.fixture)
            _print_scorecard(sc)
            return 0

        if args.benchmark_command == "diff":
            if not args.baseline or not args.candidate:
                print_error("Usage: osprey benchmark diff --baseline RUN_ID --candidate RUN_ID")
                return 2
            data = client.benchmark_diff(args.baseline, args.candidate)
            print_info(f"Diff {args.baseline} -> {args.candidate}:")
            for field, d in data["deltas"].items():
                print(f"  {field}: {d['baseline']} -> {d['candidate']} (delta={d['delta']})")
            return 0

        print_error("Usage: osprey benchmark {list|install-builtin|record|run|diff}")
        return 2
    except Exception as exc:  # noqa: BLE001
        print_error(_api_error_text(exc))
        return 1
    finally:
        client.close()


def main() -> None:
    # Load .env so API_BASE_URL / LLM_MODEL / LLM_API_KEY are available.
    # override=True so an edited .env wins over a stale value already exported in
    # the shell environment — without it, changing LLM_MODEL/LLM_API_KEY in .env
    # and relaunching kept the old model (the value inherited from the environment
    # shadowed the file), which forced a full container rebuild to change models.
    load_dotenv(override=True)

    parser = argparse.ArgumentParser(
        prog=CLI_COMMAND,
        description=f"{APP_NAME} command-line operator",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} CLI 0.1.0")
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", help="Run a scan non-interactively (scriptable/CI)")
    scan_parser.add_argument("target_arg", nargs="?", help="Domain, IP, CIDR, or URL")
    scan_parser.add_argument("--target", help="Domain, IP, CIDR, or URL")
    scan_parser.add_argument("--phase", default="full", choices=_SCAN_PHASES)
    scan_parser.add_argument("--engine", action="store_true", help="Autonomous trigger-graph engine, no LLM")
    scan_parser.add_argument("--include-low-confidence", action="store_true")
    scan_parser.add_argument("--force-new", action="store_true", help="Force a new engagement instead of reusing")

    run_parser = subparsers.add_parser("run", help="Send one prompt without opening the REPL")
    run_parser.add_argument("prompt", nargs=argparse.REMAINDER)
    run_parser.add_argument("--target", help="Bind or reuse an engagement before sending the prompt")
    run_parser.add_argument("--force-new", action="store_true", help="Force a new engagement for --target")

    bench_parser = subparsers.add_parser(
        "benchmark", help="Replay & benchmark harness (plans/harness/01-...) — record/run/diff fixtures"
    )
    bench_sub = bench_parser.add_subparsers(dest="benchmark_command")
    bench_sub.add_parser("list", help="List available fixtures")
    bench_sub.add_parser("install-builtin", help="Write the built-in synthetic fixtures to disk")
    bench_record = bench_sub.add_parser("record", help="Record a live/recent engagement as a fixture")
    bench_record.add_argument("--engagement-id", dest="engagement_id", required=True)
    bench_record.add_argument("--name", required=True)
    bench_record.add_argument("--target", default="")
    bench_run = bench_sub.add_parser("run", help="Replay a fixture and print its scorecard")
    bench_run.add_argument("--fixture", required=True)
    bench_diff = bench_sub.add_parser("diff", help="Diff two scorecards by run_id")
    bench_diff.add_argument("--baseline", required=True)
    bench_diff.add_argument("--candidate", required=True)

    args = parser.parse_args()
    if args.command == "scan":
        sys.exit(_run_scan_noninteractive(args))
    if args.command == "run":
        sys.exit(_run_prompt_noninteractive(args))
    if args.command == "benchmark":
        sys.exit(_run_benchmark_noninteractive(args))

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
            # Show all slash commands as a scrollable grid rather than a short
            # single-column list that only revealed one screenful — the command
            # set outgrew the default menu. reserve_space_for_menu gives the grid
            # real height so most commands are visible at once.
            complete_style=CompleteStyle.MULTI_COLUMN,
            reserve_space_for_menu=12,
        )
    else:
        # Piped/non-interactive stdin (CI, scripts): fall back to plain input().
        session = None

    _prompt_loop(client, session)


if __name__ == "__main__":
    main()
