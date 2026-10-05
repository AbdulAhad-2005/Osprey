"""Shared primitives for backend-spawned scoped agents: response types and
target extraction.

Everything tool-execution/system-prompt/message-hygiene related used to live
here too (``execute_agent_tool``, ``build_engagement_context``,
``prune_message_history``, ...) but existed only to serve ``phase_agent.py``'s
own ReAct loop. That loop was deleted — ``services/agent_runner.py`` now runs
a headless ``cli.agent.loop.Runner`` instead, which already has its own
tool-dispatch, system-prompt, and message-hygiene logic (the SAME logic the
interactive CLI uses) — so those functions had zero remaining callers and
were removed with it rather than kept as dead code. What's left is the two
things still genuinely shared: the response/event types ``agent_runner.py``
builds its ``AgentResponse`` from, and the target-extraction helpers
``target_binding.py`` uses independently of any agent loop.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

AgentEventHandler = Callable[[str, dict[str, Any]], Awaitable[None] | None]

_DOMAIN_RE = re.compile(
    r"(?:https?://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class AgentToolCall:
    tool_name: str
    arguments: dict[str, Any]
    result: str
    success: bool
    duration_seconds: float = 0.0


@dataclass
class AgentResponse:
    success: bool
    final_message: str
    tool_calls: list[AgentToolCall] = field(default_factory=list)
    total_duration_seconds: float = 0.0
    total_llm_calls: int = 0
    total_tool_calls: int = 0
    run_id: str = ""
    phase: str = "full"
    error: str | None = None


def response_event_payload(result: AgentResponse) -> dict[str, Any]:
    return {
        "success": result.success,
        "response": result.final_message,
        "run_id": result.run_id,
        "phase": result.phase,
        "tool_calls_count": result.total_tool_calls,
        "duration_seconds": round(result.total_duration_seconds, 2),
        "error": result.error,
        "tool_calls": [
            {
                "tool_name": tc.tool_name,
                "arguments": tc.arguments,
                "success": tc.success,
                "duration_seconds": round(tc.duration_seconds, 2),
            }
            for tc in result.tool_calls
        ],
    }


def extract_target(text: str) -> str | None:
    ip_match = _IP_RE.search(text)
    if ip_match:
        return ip_match.group(0)
    match = _DOMAIN_RE.search(text)
    if not match:
        return None
    raw = match.group(0)
    if raw.lower().startswith(("http://", "https://")):
        from urllib.parse import urlparse

        host = urlparse(raw).hostname
        return host.lower() if host else None
    return raw.lower().rstrip("/")


def extract_target_from_history(history: list[dict[str, Any]] | None) -> str | None:
    if not history:
        return None
    for msg in reversed(history):
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            found = extract_target(content)
            if found:
                return found
    return None
