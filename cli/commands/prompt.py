from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cli.api.client import APIClient

from cli.ui.display import print_agent_thinking, print_error, print_response, print_tool_call


def handle_prompt(prompt: str, client: "APIClient") -> None:
    """Send a natural language prompt to the backend agent.

    Displays tool calls as they happen and shows the final response.
    """
    if not prompt.strip():
        return

    print_agent_thinking("Agent is thinking...")

    try:
        data = client.send_prompt(prompt)

        if "error" in data and not data.get("response"):
            print_error(data["error"])
            return

        # Show tool calls inline if present
        tool_calls = data.get("tool_calls", [])
        for tc in tool_calls:
            print_tool_call(tc.get("tool_name", "?"), tc.get("arguments", {}))

        print_response(data)

    except Exception as exc:
        print_error(f"Failed to get response: {exc}")
