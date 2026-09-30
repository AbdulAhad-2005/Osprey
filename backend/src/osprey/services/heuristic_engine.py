"""No-LLM vuln/web dispatch categorization used by the harness investigation
loop, not an independently-gated engine. ``investigation_capabilities.list_step``
decides WHEN (``priority.should_unlock_phase(eid, "vuln")``) and WHICH
suggestion (``tech_dispatch.suggest_dispatch``), builds the opportunity's
tool/params directly, and runs it through the same execution kernel and
one-opportunity-one-tool-call discipline every other capability uses
(Plan 17/18) — there is no separate dispatch loop here to keep in sync.

Hard rule (operator decision): in no-LLM mode the engine runs recon→vuln and
QUEUES exploit candidates — it never launches exploitation itself.
``NON_AUTONOMOUS_CATEGORIES`` is what the opportunity generator checks
before a suggestion in the exploit/creds/post-exploitation categories is
even turned into an opportunity. When an LLM is present it drives instead
and no such restriction applies (that path is the MCP tool surface, not
this engine).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Categories the no-LLM engine must never auto-run: exploitation and anything
# downstream of a foothold. Recon/network/vuln/webapp/osint are fair game.
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
