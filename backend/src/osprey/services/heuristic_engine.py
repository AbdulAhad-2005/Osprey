"""No-LLM vuln/web dispatch categorization used by the harness investigation
loop, not an independently-gated engine. ``investigation_capabilities.list_step``
decides WHEN (``priority.should_unlock_phase(eid, "vuln")``) and WHICH
suggestion (``tech_dispatch.suggest_dispatch``), builds the opportunity's
tool/params directly, and runs it through the same execution kernel and
one-opportunity-one-tool-call discipline every other capability uses
(Plan 17/18) — there is no separate dispatch loop here to keep in sync.

Hard rule (operator decision): in no-LLM mode the engine runs recon→vuln and
QUEUES exploit candidates — it never launches exploitation itself. The
auto-run boundary keys on whether an action is read-only/safe, not which YAML
catalog it was filed under (E2): a PASSIVE tool is always engine-eligible even
in an exploit/creds/postex category (e.g. ``searchsploit_lookup`` — a read-only
local Exploit-DB lookup), while anything that sends an intrusive/stateful
payload stays behind explicit authorization. When an LLM is present it drives
instead and no such restriction applies (that path is the MCP tool surface, not
this engine).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Categories whose INTRUSIVE tools the no-LLM engine must never auto-run:
# exploitation and anything downstream of a foothold. A PASSIVE (read-only) tool
# in one of these is still eligible — see engine_may_autorun.
NON_AUTONOMOUS_CATEGORIES: frozenset[str] = frozenset({"exploit", "creds", "postex"})


def _category_of(tool_name: str) -> str:
    """Registered category for a tool, or '' if unknown (unknown → never blocked,
    since a blocklist should only ever exclude tools we can positively classify)."""
    try:
        from osprey.services.tool_registry import get_tool_definition

        td = get_tool_definition(tool_name)
        if td is not None:
            return str(getattr(td.category, "value", td.category) or "")
    except Exception as exc:  # noqa: BLE001
        logger.debug("category lookup failed for %s: %s", tool_name, exc)
    return ""


def _safety_of(tool_name: str) -> str:
    """Registered safety level ('passive'|'active'|'gated'), or '' if unknown."""
    try:
        from osprey.services.tool_registry import get_tool_definition

        td = get_tool_definition(tool_name)
        if td is not None:
            return str(getattr(td.safety_level, "value", td.safety_level) or "")
    except Exception as exc:  # noqa: BLE001
        logger.debug("safety lookup failed for %s: %s", tool_name, exc)
    return ""


def engine_may_autorun(tool_name: str) -> bool:
    """Whether the no-LLM engine may turn this tool into an opportunity (E2).
    A read-only (PASSIVE) tool is always eligible; otherwise a tool in a
    non-autonomous category (exploit/creds/postex) is gated behind explicit
    authorization."""
    if _safety_of(tool_name) == "passive":
        return True
    return _category_of(tool_name) not in NON_AUTONOMOUS_CATEGORIES
