"""The CLI's tool layer — imports `platform-mcp/server.py` directly.

This is the same tool surface an external MCP harness (OpenCode, Claude
Desktop) already drives Osprey through. Reusing it here means the CLI's
local agent loop has zero second tool-definition surface, zero second
context/skills/conductor-signal assembly, and — as a side effect — the
"shared MCP subprocess across chats" bug documented in that module doesn't
apply: one CLI process is one operator's own session by construction.

`@mcp.tool()` (FastMCP) does not modify the decorated function — it just
registers it and returns the original callable — so every tool Osprey has,
static or dynamically-registered, is reachable through one path:
`FastMCP._tool_manager.get_tool(name).fn`, called via `asyncio.to_thread`
because these are synchronous, blocking-HTTP functions.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any

_SERVER_MODULE: Any = None


def _platform_mcp_dir() -> Path:
    # cli/agent/tools.py -> repo root -> platform-mcp/
    return Path(__file__).resolve().parents[2] / "platform-mcp"


def load_server(api_base_url: str) -> Any:
    """Import platform-mcp/server.py once, pointed at the CLI's own backend URL.

    `server.py` reads `PENTEST_API_BASE` at import time — set it (only if the
    operator hasn't already exported one explicitly) before the first import
    so the CLI's tool calls land on the same backend the rest of the CLI is
    configured against, not always localhost.

    `PENTEST_RUN_ID` is set the same way, to a fresh value, for a real reason:
    server.py mirrors its bound target/engagement to a temp file keyed by this
    id, purely so an MCP HOST that respawns its OWN subprocess mid-conversation
    can recover the binding. When unset it defaults to the literal string
    "default" — which means every CLI launch on a machine, with no relation to
    each other, silently shares and inherits that same file. This CLI has no
    subprocess to respawn (one long-lived process is the whole session), so
    that recovery scenario never applies here; giving each launch its own id
    is what makes a genuinely new session start with a genuinely clean slate,
    not a patch layered on top of the sharing.

    `PENTEST_MCP_QUIET` tells server.py's own `_log()` (a raw stderr print
    meant for an MCP host's hidden log stream) to stay silent — this CLI
    renders its own tool-call events instead, so those prints would otherwise
    land straight in the interactive terminal.
    """
    global _SERVER_MODULE
    if _SERVER_MODULE is not None:
        return _SERVER_MODULE

    os.environ.setdefault("PENTEST_API_BASE", api_base_url)
    os.environ.setdefault("PENTEST_RUN_ID", uuid.uuid4().hex[:12])
    os.environ.setdefault("PENTEST_MCP_QUIET", "1")

    mcp_dir = str(_platform_mcp_dir())
    if mcp_dir not in sys.path:
        sys.path.insert(0, mcp_dir)

    import server as _server  # noqa: PLC0415 — deliberate late import, see above

    _SERVER_MODULE = _server
    return _server


def get_tool_schemas() -> list[dict[str, Any]]:
    """OpenAI-style function-calling schema for every registered tool.

    Sourced from FastMCP's own tool manager — the exact schema an external
    MCP harness already sees via `tools/list`. Not regenerated, not a second
    schema builder.
    """
    server = _SERVER_MODULE
    if server is None:
        raise RuntimeError("load_server() must be called before get_tool_schemas()")

    schemas: list[dict[str, Any]] = []
    for tool in server.mcp._tool_manager.list_tools():
        schemas.append(
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": (tool.description or "")[:1024],
                    "parameters": tool.parameters
                    or {"type": "object", "properties": {}},
                },
            }
        )
    return schemas


async def call_tool(name: str, arguments: dict[str, Any]) -> str:
    """Execute one tool call by name, off the event loop (these are blocking
    HTTP calls under the hood — same cost model as the MCP path)."""
    server = _SERVER_MODULE
    if server is None:
        raise RuntimeError("load_server() must be called before call_tool()")

    tool = server.mcp._tool_manager.get_tool(name)
    if tool is None:
        return f"ERROR: no such tool '{name}'."

    # Drop any key the LLM hallucinated that isn't a real parameter, rather
    # than letting a stray kwarg crash the call with a raw TypeError.
    allowed = set((tool.parameters or {}).get("properties", {}).keys())
    clean_args = {k: v for k, v in (arguments or {}).items() if k in allowed}

    try:
        result = await asyncio.to_thread(tool.fn, **clean_args)
    except Exception as exc:  # noqa: BLE001 — surface as a tool result, not a crash
        return f"ERROR executing {name}: {exc}"

    return result if isinstance(result, str) else str(result)


def current_engagement_id() -> str:
    server = _SERVER_MODULE
    return getattr(server, "_SESSION_ENGAGEMENT_ID", "") if server else ""


def current_target() -> str:
    server = _SERVER_MODULE
    return getattr(server, "_SESSION_TARGET", "") if server else ""
