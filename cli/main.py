from __future__ import annotations

import os
import sys

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

    from cli.api.client import APIClient
    from cli.commands.prompt import handle_prompt
    from cli.commands.slash import SLASH_COMMANDS, execute_command
    from cli.ui.display import print_banner, print_error, print_info
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


def _prompt_loop(client: APIClient, session) -> None:
    """Read + dispatch loop. ``session`` is a prompt_toolkit session (TTY) or None (piped)."""
    try:
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

            if text.startswith("/"):
                should_continue = execute_command(text, client)
                if not should_continue:
                    break
            else:
                handle_prompt(text, client)

    finally:
        client.close()
        print_info("Session ended.")


def main() -> None:
    # Load .env so API_BASE_URL and other env vars are available
    load_dotenv()

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