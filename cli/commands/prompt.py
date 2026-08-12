from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.ui.display import consume_agent_stream, print_error


def handle_prompt(prompt: str, client: "APIClient") -> None:
    """Send a natural language prompt to the backend agent with live terminal output."""
    if not prompt.strip():
        return

    try:
        stream = client.send_prompt_stream(prompt, engagement_id=client.active_engagement_id)
        final = consume_agent_stream(stream)

        if final is None:
            print_error("Agent stream ended without a final response.")
            return

        if not final.get("success", True) and final.get("error"):
            print_error(final["error"])

    except Exception as exc:
        print_error(f"Failed to get response: {exc}")
