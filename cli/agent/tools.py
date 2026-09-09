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


# The bootstrap set for budget-constrained providers (see get_tool_schemas'
# budget_tokens param) — small enough to fit almost any free-tier limit, and
# sufficient on its own to reach every OTHER registered tool indirectly:
# platform_tools searches the full catalog by name/keyword, platform_exec
# invokes any tool found that way by name + a loose params_json (no
# structured schema required — see its own docstring). Nothing outside this
# set becomes uncallable when trimmed; it's one extra round trip (search,
# then invoke) instead of a direct structured call. call_tool() below always
# resolves against the FULL tool manager regardless of what schemas were
# ever advertised to the model, so this is genuinely just a smaller menu,
# never a smaller capability.
_BOOTSTRAP_TOOL_NAMES = frozenset(
    {
        "platform_context",
        "platform_set_target",
        "platform_shell",
        "platform_script",
        "platform_exec",
        "platform_tools",
        "platform_findings",
        "platform_skills",
    }
)

# Rough chars-per-token used only to size the trimmed schema list against a
# provider's token-per-minute budget — a soft estimate, not a tokenizer;
# the margin below (see get_tool_schemas) absorbs the slop.
_CHARS_PER_TOKEN_ESTIMATE = 4


def _schema_for(tool: Any) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": (tool.description or "")[:1024],
            "parameters": tool.parameters or {"type": "object", "properties": {}},
        },
    }


def get_tool_schemas(*, budget_tokens: int = 0) -> list[dict[str, Any]]:
    """OpenAI-style function-calling schema for registered tools.

    Sourced from FastMCP's own tool manager — the exact schema an external
    MCP harness already sees via `tools/list`. Not regenerated, not a second
    schema builder.

    budget_tokens=0 (default): every registered tool, exactly as always —
    this is the whole catalog, unfiltered, for any model/provider with
    enough context and per-minute-token budget to take it (which is most of
    them; this was the CLI's only behavior before budget_tokens existed, and
    stays byte-for-byte identical when the operator hasn't opted into a
    limit). budget_tokens>0: a provider-imposed ceiling (set via
    LLM_TOOL_SCHEMA_BUDGET_TOKENS in .env, for a specific free-tier limit
    that's smaller than the full catalog) — send the bootstrap set in full,
    then fill the remaining budget with as many other tools as fit. Never
    silently drops capability: search (platform_tools) + generic invoke
    (platform_exec) reach everything not sent directly.
    """
    server = _SERVER_MODULE
    if server is None:
        raise RuntimeError("load_server() must be called before get_tool_schemas()")

    all_tools = list(server.mcp._tool_manager.list_tools())
    if budget_tokens <= 0:
        return [_schema_for(tool) for tool in all_tools]

    # 10% margin: the schema list isn't the only thing counted against a
    # per-minute token budget — the conversation history and the model's own
    # response share it too.
    remaining_chars = int(budget_tokens * _CHARS_PER_TOKEN_ESTIMATE * 0.9)

    bootstrap = [t for t in all_tools if t.name in _BOOTSTRAP_TOOL_NAMES]
    rest = [t for t in all_tools if t.name not in _BOOTSTRAP_TOOL_NAMES]

    schemas: list[dict[str, Any]] = []
    for tool in bootstrap:
        schema = _schema_for(tool)
        schemas.append(schema)
        remaining_chars -= len(str(schema))
    for tool in rest:
        schema = _schema_for(tool)
        cost = len(str(schema))
        if cost > remaining_chars:
            continue
        schemas.append(schema)
        remaining_chars -= cost
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
