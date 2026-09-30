"""The CLI adapter for Osprey's embedded capability gateway.

This is the same tool surface an external MCP harness (OpenCode, Claude
Desktop) already drives Osprey through. Reusing it here means the CLI's
local agent loop has zero second tool-definition surface, zero second
context/skills/conductor-signal assembly, and — as a side effect — the
"shared MCP subprocess across chats" bug documented in that module doesn't
apply: one CLI process is one operator's own session by construction.

FastMCP-private access is contained behind the platform adapter's public
embedding API. Calls run via ``asyncio.to_thread`` because the embedded
handlers perform synchronous backend HTTP requests.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import uuid
from pathlib import Path
from typing import Any

_SERVER_MODULE: Any = None


class EmbeddedToolGateway:
    """Application-owned façade over the embedded MCP adapter.

    FastMCP internals and module-global session state are contained behind the
    platform adapter's public embedding API.  The CLI harness and Runner
    depend on this small contract, never on adapter-private registries.
    """

    def __init__(self, api_base_url: str) -> None:
        self.api_base_url = api_base_url.rstrip("/")
        self.engagement_id = ""
        self.target = ""
        self._loaded = False

    def activate(self) -> None:
        load_server(self.api_base_url)
        self._loaded = True
        if self.engagement_id:
            bind_session(engagement_id=self.engagement_id, target=self.target)

    def configure(self, api_base_url: str) -> None:
        self.api_base_url = api_base_url.rstrip("/")
        if self._loaded:
            reconfigure_server(self.api_base_url)
            if self.engagement_id:
                bind_session(engagement_id=self.engagement_id, target=self.target)

    def bind(self, *, engagement_id: str, target: str = "") -> None:
        self.engagement_id = engagement_id.strip()
        self.target = target.strip()
        if self._loaded:
            bind_session(engagement_id=self.engagement_id, target=self.target)

    def schemas(self, *, budget_tokens: int = 0) -> list[dict[str, Any]]:
        if not self._loaded:
            self.activate()
        return get_tool_schemas(budget_tokens=budget_tokens)

    async def call(self, name: str, arguments: dict[str, Any]) -> str:
        if not self._loaded:
            self.activate()
        return await call_tool(name, arguments)


def _platform_mcp_dir() -> Path:
    # cli/agent/tools.py -> repo root -> platform-mcp/
    return Path(__file__).resolve().parents[2] / "platform-mcp"


def load_server(api_base_url: str) -> Any:
    """Import platform-mcp/server.py once, pointed at the CLI's own backend URL.

    `server.py` reads `PENTEST_API_BASE` at import time — set it to the CLI's
    selected backend before the first import
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
        desired = api_base_url.rstrip("/")
        if str(getattr(_SERVER_MODULE, "API_BASE", "")).rstrip("/") != desired:
            _SERVER_MODULE.embedded_reconfigure(desired)
        return _SERVER_MODULE

    # The CLI's selected API URL is authoritative for its embedded gateway.
    # Honouring a stale, unrelated PENTEST_API_BASE here creates a split-brain
    # session where slash commands and agent tools reach different backends.
    os.environ["PENTEST_API_BASE"] = api_base_url.rstrip("/")
    os.environ.setdefault("PENTEST_RUN_ID", uuid.uuid4().hex[:12])
    os.environ.setdefault("PENTEST_MCP_QUIET", "1")

    mcp_dir = str(_platform_mcp_dir())
    if mcp_dir not in sys.path:
        sys.path.insert(0, mcp_dir)

    module_name = "_osprey_embedded_platform_mcp"
    spec = importlib.util.spec_from_file_location(
        module_name, _platform_mcp_dir() / "server.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load Osprey's embedded capability gateway")
    _server = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = _server
    spec.loader.exec_module(_server)

    _SERVER_MODULE = _server
    return _server


def reconfigure_server(api_base_url: str) -> None:
    """Point the already-imported embedded gateway at a reconnected backend.

    Clear its ambient target too: an engagement id from the previous backend is
    not safe to reuse against the new URL.  The next Runner bind establishes the
    exact target/engagement pair again.
    """
    os.environ["PENTEST_API_BASE"] = api_base_url.rstrip("/")
    server = _SERVER_MODULE
    if server is None:
        return
    server.embedded_reconfigure(api_base_url)


def bind_session(*, engagement_id: str, target: str = "") -> None:
    """Synchronize the embedded gateway with APIClient's explicit binding.

    The CLI already resolved this exact engagement through REST.  Mirroring the
    resolved identity avoids a second target resolution (which could select a
    different force-created engagement) while ensuring ambient-only MCP tools
    and explicitly pinned tools agree on the same engagement.
    """
    server = _SERVER_MODULE
    if server is None:
        raise RuntimeError("load_server() must be called before bind_session()")
    server.embedded_bind_session(engagement_id=engagement_id, target=target)


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
        "platform_investigation_step",
        "platform_investigation_execute",
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


def _schema_for(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": (tool.get("description") or "")[:1024],
            "parameters": tool.get("parameters") or {"type": "object", "properties": {}},
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

    all_tools = server.embedded_tool_specs()
    if budget_tokens <= 0:
        return [_schema_for(tool) for tool in all_tools]

    # The schema list is only ONE of three things sharing this per-minute
    # budget — the system prompt (platform_context's own output can be
    # substantial on its own) and the conversation history (which
    # Runner._trim_history_for_budget bounds against whatever's left after
    # THIS reservation) take the rest. Giving schemas the full 90% — as an
    # earlier version of this did — left so little headroom that real
    # multi-turn sessions ran over budget within 2-3 exchanges even with a
    # trimmed schema list: the schema was no longer the problem, but it was
    # still eating the room the other two needed. Half-and-half is a much
    # safer split; the bootstrap set (always included, see below) is what
    # actually matters for capability, not how many "extra" tools fit on
    # top of it.
    remaining_chars = int(budget_tokens * _CHARS_PER_TOKEN_ESTIMATE * 0.5)

    bootstrap = [t for t in all_tools if t["name"] in _BOOTSTRAP_TOOL_NAMES]
    rest = [t for t in all_tools if t["name"] not in _BOOTSTRAP_TOOL_NAMES]

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

    try:
        result = await asyncio.to_thread(server.embedded_invoke_tool, name, arguments or {})
    except KeyError:
        return f"ERROR: no such tool '{name}'."
    except Exception as exc:  # noqa: BLE001 — surface as a tool result, not a crash
        return f"ERROR executing {name}: {exc}"

    return result if isinstance(result, str) else str(result)
