"""
Platform MCP gateway for OpenCode / Claude Desktop.

Dynamic multi-target: call platform_set_target(domain) when the user names a
target. Each distinct root domain gets its own engagement_id and isolated
Postgres storage. Switching targets in the same chat rebinds automatically.
"""

from __future__ import annotations

import uuid
from typing import Any

import _gateway_core as _core
from _gateway_core import (
    _ENGAGEMENT_CACHE,
    _ENGAGEMENT_RUN_IDS,
    _INVOCATION_ENGAGEMENT,
    _clear_session,
    _ensure_run_registered,
    _log,
    _persist_session,
    _safe,
    mcp,
)
from typed_app_analysis import register_typed_app_analysis_tools
from typed_browser import register_typed_browser_tools
from typed_exploit import register_typed_exploit_tools
from typed_osint import register_typed_osint_tools
from typed_proxy import register_typed_proxy_tools
from typed_recon_content import register_typed_recon_content_tools
from typed_recon_network import register_typed_recon_network_tools
from typed_tech_identification import register_typed_tech_identification_tools
from typed_vuln import register_typed_vuln_tools
from typed_web_search import register_typed_web_search_tools

# Importing these registers every @mcp.tool / @mcp.prompt onto _core.mcp.
import _gateway_context  # noqa: E402,F401
import _gateway_exec  # noqa: E402,F401
import _gateway_findings  # noqa: E402,F401
import _gateway_knowledge  # noqa: E402,F401
import _gateway_session  # noqa: E402,F401
from _gateway_exec import _execute_catalog_tool  # noqa: E402


def _typed_execute(
    tool_name: str,
    params: dict[str, Any],
    *,
    additional_args: str = "",
    timeout_seconds: int = 300,
    engagement_id: str = "",
    blast_radius: str = "",
    exploit_candidate_id: str = "",
) -> str:
    return _safe(
        lambda: _execute_catalog_tool(
            tool_name,
            params,
            additional_args=additional_args,
            timeout_seconds=timeout_seconds,
            engagement_id=engagement_id,
            blast_radius=blast_radius,
            exploit_candidate_id=exploit_candidate_id,
        )
    )




_TYPED_COUNT = register_typed_recon_network_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_COUNT} typed recon/network tools")

_TYPED_TECH_COUNT = register_typed_tech_identification_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_TECH_COUNT} typed tech-identification tools")

_TYPED_OSINT_COUNT = register_typed_osint_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_OSINT_COUNT} typed passive-OSINT tools")

_TYPED_CONTENT_COUNT = register_typed_recon_content_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_CONTENT_COUNT} typed recon-content tools")

_TYPED_APP_COUNT = register_typed_app_analysis_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_APP_COUNT} typed app-analysis tools")

_TYPED_VULN_COUNT = register_typed_vuln_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_VULN_COUNT} typed vulnerability-analysis tools")

_TYPED_BROWSER_COUNT = register_typed_browser_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_BROWSER_COUNT} typed browser-automation tools")

_TYPED_PROXY_COUNT = register_typed_proxy_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_PROXY_COUNT} typed traffic-capture tools")

_TYPED_WEB_SEARCH_COUNT = register_typed_web_search_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_WEB_SEARCH_COUNT} typed web-search tools")

_TYPED_EXPLOIT_COUNT = register_typed_exploit_tools(mcp, execute=_typed_execute)
_log(f"registered {_TYPED_EXPLOIT_COUNT} typed exploitation/creds/cloud-exploit tools")

# Optional private-overlay typed tools (for example, a company credential
# manager). Absent in
# public Osprey — a missing module is a no-op, not an error.
try:
    from typed_private import register_typed_private_tools  # type: ignore

    _TYPED_PRIVATE_COUNT = register_typed_private_tools(mcp, execute=_typed_execute)
    _log(f"registered {_TYPED_PRIVATE_COUNT} typed private-overlay tools")
except ImportError:
    pass


# Public embedding API.  FastMCP is an adapter for Osprey's capabilities, not
# the application API consumed by the first-party CLI.  Keep every private
# FastMCP/session-global touch on this side of the boundary.

def embedded_tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.parameters or {"type": "object", "properties": {}},
        }
        for tool in mcp._tool_manager.list_tools()
    ]


def embedded_invoke_tool(name: str, arguments: dict[str, Any], *, engagement_id: str = "") -> Any:
    tool = mcp._tool_manager.get_tool(name)
    if tool is None:
        raise KeyError(name)
    allowed = set((tool.parameters or {}).get("properties", {}).keys())
    clean_args = {key: value for key, value in (arguments or {}).items() if key in allowed}
    if engagement_id and "engagement_id" in allowed and not str(clean_args.get("engagement_id") or "").strip():
        clean_args["engagement_id"] = engagement_id
    token = _INVOCATION_ENGAGEMENT.set(engagement_id)
    try:
        return tool.fn(**clean_args)
    finally:
        _INVOCATION_ENGAGEMENT.reset(token)


def embedded_bind_session(*, engagement_id: str, target: str = "") -> None:
    _core._SESSION_ENGAGEMENT_ID = (engagement_id or "").strip()
    _core._SESSION_TARGET = (target or "").strip()
    # The CLI has an already-resolved engagement but does not own a target
    # parser.  Keep the identity opaque instead of falsely labeling every IP,
    # CIDR, URL, and host:port as a domain.
    _core._SESSION_TARGET_KIND = "target"
    _core._SESSION_SCOPE = ""
    _core._SESSION_SWITCH_NOTICE = ""
    if _core._SESSION_ENGAGEMENT_ID:
        _ENGAGEMENT_CACHE[_core._SESSION_ENGAGEMENT_ID] = {
            "target": _core._SESSION_TARGET,
            "kind": _core._SESSION_TARGET_KIND,
            "scope": "",
        }
        _core.SESSION_RUN_ID = _ENGAGEMENT_RUN_IDS.setdefault(_core._SESSION_ENGAGEMENT_ID, uuid.uuid4().hex[:12])
        _ensure_run_registered(_core._SESSION_ENGAGEMENT_ID, _core.SESSION_RUN_ID)
    _persist_session()


def embedded_reconfigure(api_base_url: str) -> None:
    old_client = _core._HTTP_CLIENT
    _core._HTTP_CLIENT = None
    if old_client is not None:
        try:
            old_client.close()
        except Exception:
            pass
    _core.API_BASE = api_base_url.rstrip("/")
    _clear_session()


def embedded_session_context() -> dict[str, str]:
    return {
        "engagement_id": _core._SESSION_ENGAGEMENT_ID,
        "target": _core._SESSION_TARGET,
    }


def __getattr__(name: str) -> Any:
    # Re-export the kernel's live session state (API_BASE, _SESSION_*, and
    # helpers) so consumers that read attributes off this module — e.g. the
    # CLI gateway loader checking API_BASE — observe _gateway_core's current
    # values rather than a snapshot frozen at import time.
    try:
        return getattr(_core, name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


if __name__ == "__main__":
    _log(f"session run_id={_core.SESSION_RUN_ID} (dynamic target — call platform_set_target first)")
    mcp.run()
