from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.ui.display import print_error, print_info, print_response


def handle_prompt(prompt: str, client: "APIClient") -> None:
    """Send a natural language prompt to the backend agent."""
    if not prompt.strip():
        return

    print_info("Thinking...")
    try:
        data = client.send_prompt(prompt)
        print_response(data)
    except Exception as exc:
        print_error(f"Failed to get response: {exc}")
