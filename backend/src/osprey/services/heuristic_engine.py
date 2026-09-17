"""No-LLM heuristic dispatch engine — the deterministic vuln/web decision stage.

The recon breadth engine (``surface_expansion.run_expansion_to_fixpoint``) already
maps the attack surface without an LLM. What it lacks is the *decision layer* the
ticket calls for: given the tech/services recon surfaced, deterministically pick
and run the vuln/web tools that match — nuclei on a fingerprinted stack, wpscan on
WordPress, sslyze on a TLS host, sqlmap on injection-point candidates — the same
choices the LLM makes from ``tech_dispatch``, but by rule instead of by reasoning.

This is a *peer* to Commander, not a mode inside it. It reuses, with zero
duplication:
  * ``tech_dispatch.suggest_dispatch`` — the signal→tool decision table (the rules).
  * ``tool_execution.execute_tool_request`` — the ONE execution kernel (governance,
    caching, parsing, findings ingest). No second tool-wrapper surface.
  * ``sufficiency`` phase gating and ``exploit_candidate_store`` for queueing.

Hard rule (operator decision): in no-LLM mode the engine runs recon→vuln and
QUEUES exploit candidates — it never launches exploitation itself. Tools in the
exploit/creds/post-exploitation categories are never auto-run here. When an LLM is
present it drives instead and no such restriction applies (that path is the MCP
tool surface, not this engine).

The pick is a pure function (``select_next_dispatch``) so the decision logic is
unit-testable without a DB or a live tool; the async ``run_dispatch_stage`` wraps
it with the kernel and a bounded step budget.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from osprey.schemas.hybrid import DispatchSuggestion

logger = logging.getLogger(__name__)

# Categories the no-LLM engine must never auto-run: exploitation and anything
# downstream of a foothold. Recon/network/vuln/webapp/osint are fair game.
NON_AUTONOMOUS_CATEGORIES: frozenset[str] = frozenset({"exploit", "creds", "postex"})


def dispatch_key(s: DispatchSuggestion) -> str:
    """Identity of a dispatch for de-duplication: the tool plus its rule-specific
    flags (so a plain `httpx_probe` and `httpx_probe -path /wp-json` are distinct
    actions, but the same rule twice is one)."""
    return f"{s.default_tool}::{s.additional_args}".strip()


def select_next_dispatch(
    suggestions: list[DispatchSuggestion],
    *,
    executed_keys: set[str],
    category_of: Callable[[str], str],
    blocked_categories: frozenset[str] = NON_AUTONOMOUS_CATEGORIES,
) -> DispatchSuggestion | None:
    """Highest-priority dispatch not yet executed and not in a blocked category.

    ``suggestions`` is assumed priority-sorted (suggest_dispatch guarantees it),
    but this re-sorts defensively so the function is correct on any input. Returns
    None at fixpoint — every current suggestion has already run or is blocked.
    """
    for s in sorted(suggestions, key=lambda x: x.priority, reverse=True):
        if not s.default_tool:
            continue
        if dispatch_key(s) in executed_keys:
            continue
        if category_of(s.default_tool) in blocked_categories:
            continue
        return s
    return None


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


async def run_dispatch_stage(
    *,
    engagement_id: str,
    run_id: str = "",
    max_steps: int = 25,
    on_progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run the deterministic vuln/web dispatch loop to fixpoint or ``max_steps``.

    Each step: re-read the dispatch suggestions (they shift as findings accrue),
    pick the top not-yet-run, non-exploit tool, and run it through the kernel.
    Best-effort — one tool failure never aborts the stage (the kernel already
    records failures + auto-fallbacks). Returns a summary of what ran.
    """
    eid = (engagement_id or "").strip()
    if not eid:
        return {"error": "engagement_id required", "steps": 0, "executed": []}

    from osprey.schemas.tools import ToolExecutionRequest
    from osprey.services.tech_dispatch import suggest_dispatch
    from osprey.services.tool_execution import execute_tool_request

    executed_keys: set[str] = set()
    executed: list[dict[str, str]] = []
    stopped_reason = "fixpoint"

    def _progress(msg: str) -> None:
        if on_progress is not None:
            try:
                on_progress(msg)
            except Exception:  # noqa: BLE001
                logger.debug("on_progress failed (non-fatal)", exc_info=True)

    for step in range(1, max_steps + 1):
        suggestions = suggest_dispatch(engagement_id=eid, run_id=run_id)
        pick = select_next_dispatch(
            suggestions, executed_keys=executed_keys, category_of=_category_of
        )
        if pick is None:
            stopped_reason = "fixpoint"
            break

        executed_keys.add(dispatch_key(pick))
        _progress(f"engine: {pick.default_tool} — {pick.reason or pick.task_id}")
        try:
            await execute_tool_request(
                ToolExecutionRequest(
                    tool_name=pick.default_tool,
                    params={},  # kernel injects the seed target when omitted
                    engagement_id=eid,
                    run_id=run_id,
                    additional_args=pick.additional_args or "",
                    use_recovery=True,
                    record_findings=True,
                )
            )
            executed.append({"tool": pick.default_tool, "reason": pick.reason})
        except Exception as exc:  # noqa: BLE001 — a tool failure never aborts the stage
            logger.info("engine step %d (%s) failed non-fatally: %s", step, pick.default_tool, exc)
            executed.append({"tool": pick.default_tool, "reason": pick.reason, "error": str(exc)[:200]})
    else:
        stopped_reason = "max_steps"

    return {
        "engagement_id": eid,
        "steps": len(executed),
        "executed": executed,
        "stopped_reason": stopped_reason,
    }
