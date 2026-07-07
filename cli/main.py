from __future__ import annotations

import os
import sys

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import InMemoryHistory

from cli.api.client import APIClient
from cli.commands.slash import SLASH_COMMANDS, execute_command
from cli.commands.prompt import handle_prompt
from cli.ui.display import print_banner, print_error, print_info


class CommandCompleter(Completer):
    """Autocomplete for slash commands."""

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if text.startswith("/"):
            for cmd, (desc, _) in SLASH_COMMANDS.items():
                if cmd.startswith(text):
                    yield Completion(cmd, start_position=-len(text), display_meta=desc)


def main() -> None:
    api_url = os.getenv("API_BASE_URL", "http://localhost:8000")
    client = APIClient(base_url=api_url)

    print_banner()
    print_info(f"Connected to: {api_url}")

    session = PromptSession(
        completer=CommandCompleter(),
        history=InMemoryHistory(),
    )

    try:
        while True:
            try:
                user_input = session.prompt("pentest> ", complete_while_typing=True)
            except KeyboardInterrupt:
                continue
            except EOFError:
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


if __name__ == "__main__":
    main()
