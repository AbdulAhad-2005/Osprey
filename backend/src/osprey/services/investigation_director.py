"""``InvestigationDirector`` — plans/harness/09-dual-mode-planner.md Step 2.

The ONE loop: assemble state -> planner decides -> capability runs -> evidence
-> observations -> world-model update -> repeat. Replaces the two prior
entry points (``surface_expansion.run_expansion_to_fixpoint``'s recon-only
loop, and ``phase_supervisor.run_pipeline``'s LLM-agent-spawn loop) that used
to be driven by different, separately-hand-rolled stopping logic. The
CAPABILITIES underneath (``run_expansion_pass``, ``run_dispatch_stage``,
agent spawning) are NOT rewritten — plans/harness/09 Step 2b is explicit that
"folds into the planner" must not mean "rewrite from memory": this director
only changes WHO decides to call them and WHEN, replacing a boolean flag
(``include_vuln_dispatch``) and a hardcoded pass/step budget with the real
priority signal (plans/harness/06).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

from osprey.schemas.planner import ActionKind
from osprey.services.planner import DeterministicPlanner, PlannerState

logger = logging.getLogger(__name__)

_TITLE_SAMPLE_CAP = 20


async def run_to_completion(
    *,
    engagement_id: str,
    run_id: str,
    max_passes: int = 5,
    on_pass: Callable[[Any], None] | None = None,
    on_progress: Callable[[str], None] | None = None,
    min_origin_confidence: float | None = None,
    max_vuln_steps: int = 25,
) -> Any:
    """No-LLM investigation to fixpoint — the ``DeterministicPlanner``-driven
    path. Same return shape as the old ``run_expansion_to_fixpoint``
    (``ExpansionReport``) so callers (job_store's EXPANSION job kind,
    ``platform_expand``) don't need their own contract to change; what
    changed is that the vuln-dispatch stage now runs because
    ``priority.should_unlock_phase`` says there's real evidence to work with,
    not because a caller passed ``include_vuln_dispatch=True`` unconditionally.
    """
    from osprey.services.exploit_candidate_store import get_exploit_candidate_store
    from osprey.services.exploit_pipeline import scan_for_candidates
    from osprey.services.findings_store import get_findings_store
    from osprey.services.heuristic_engine import run_dispatch_stage
    from osprey.services.surface_expansion import (
        _MIN_ORIGIN_CONFIDENCE,
        _origin_confidence,
        ExpansionReport,
        PassReport,
        run_expansion_pass,
    )
    from osprey.services.engagement_graph import get_engagement_graph
    from osprey.schemas.engagement_graph import AssetType

    eid = (engagement_id or "").strip()
    if not eid:
        return ExpansionReport(engagement_id=eid, passes=[], exhausted=False, stopped_reason="max_passes")

    min_conf = _MIN_ORIGIN_CONFIDENCE if min_origin_confidence is None else min_origin_confidence
    planner = DeterministicPlanner()
    state = PlannerState(engagement_id=eid)
    findings_store = get_findings_store()

    passes: list[Any] = []
    exhausted = False
    recon_pass_count = 0

    while True:
        action = planner.decide_next_action(state)

        if action.kind == ActionKind.EXPAND_RECON:
            recon_pass_count += 1
            before_ids = {f.id for f in findings_store.list(engagement_id=eid, limit=5000)}
            delta = await run_expansion_pass(
                engagement_id=eid, run_id=run_id, on_progress=on_progress, min_origin_confidence=min_conf,
            )
            after = findings_store.list(engagement_id=eid, limit=5000)
            new_titles = [f.title for f in after if f.id not in before_ids][:_TITLE_SAMPLE_CAP]
            pass_report = PassReport(pass_number=recon_pass_count, delta=delta, new_finding_titles=new_titles)
            passes.append(pass_report)
            if on_pass is not None:
                try:
                    on_pass(pass_report)
                except Exception:
                    logger.debug("on_pass callback failed (non-fatal)", exc_info=True)
            if delta.exhausted or delta.frontier_processed == 0 or recon_pass_count >= max_passes:
                state.recon_exhausted = True
                exhausted = exhausted or delta.exhausted
            continue

        if action.kind == ActionKind.VULN_DISPATCH:
            if on_progress is not None:
                on_progress(f"director: {action.reason} — running vuln dispatch")
            try:
                dispatch_summary = await run_dispatch_stage(
                    engagement_id=eid, run_id=run_id, max_steps=max_vuln_steps, on_progress=on_progress,
                )
                logger.info(
                    "director vuln dispatch ran %d tool(s) for %s (%s)",
                    dispatch_summary.get("steps", 0), eid, dispatch_summary.get("stopped_reason"),
                )
            except Exception:  # noqa: BLE001 — never let the vuln stage abort the whole run
                logger.exception("vuln dispatch failed (non-fatal); continuing")
            state.vuln_exhausted = True
            continue

        # ActionKind.NONE — nothing left above the priority threshold.
        break

    candidates_before = {c.id for c in get_exploit_candidate_store().list_for_engagement(eid)}
    candidates = scan_for_candidates(engagement_id=eid, run_id=run_id)
    new_candidates = [c for c in candidates if c.id not in candidates_before]

    graph = get_engagement_graph()
    held_back = [
        f"{n.label} (confidence {_origin_confidence(n):.1f})"
        for n in graph.list_nodes(engagement_id=eid, asset_type=AssetType.HOST, limit=5000)
        if n.metadata.get("held_back_low_confidence") and not n.metadata.get("host_expanded")
    ]
    held_back_sisters_raw = [
        f"{n.label} ({n.metadata.get('hunter_confidence', '?')})"
        for n in graph.list_nodes(engagement_id=eid, asset_type=AssetType.HOST, limit=5000)
        if n.metadata.get("role") == "sister_domain"
    ]
    seen_sisters: set[str] = set()
    deduped_sisters: list[str] = []
    for entry in held_back_sisters_raw:
        label = entry.split(" ", 1)[0]
        if label not in seen_sisters:
            seen_sisters.add(label)
            deduped_sisters.append(entry)

    if held_back and on_progress is not None:
        shown = ", ".join(held_back[:8])
        tail = f" (+{len(held_back) - 8} more)" if len(held_back) > 8 else ""
        on_progress(
            f"RESULT::⚠ {len(held_back)} low-confidence candidate(s) held back, not scanned — "
            f"{shown}{tail}. Re-run with --include-low-confidence to expand them too."
        )
    if deduped_sisters and on_progress is not None:
        shown = ", ".join(deduped_sisters[:8])
        tail = f" (+{len(deduped_sisters) - 8} more)" if len(deduped_sisters) > 8 else ""
        on_progress(
            f"RESULT::ⓘ {len(deduped_sisters)} associated domain(s) discovered but not worked on — "
            f"{shown}{tail}. Only the seed domain + its subdomains were scanned. "
            f"Say the word to expand any of them (set work_sisters: true in config/expansion.yaml)."
        )

    return ExpansionReport(
        engagement_id=eid,
        passes=passes,
        exhausted=exhausted,
        stopped_reason="exhausted" if exhausted else "max_passes",
        new_candidate_count=len(new_candidates),
        new_candidate_samples=[
            f"{c.promotion_trigger}: {c.evidence_summary[:80]}" for c in new_candidates[:10]
        ],
        held_back_low_confidence=held_back,
        held_back_sisters=deduped_sisters,
    )


async def run_agent_driven_pipeline(
    *,
    engagement_id: str,
    run_id: str = "",
    on_event: Callable[[str, dict[str, Any]], Any] | None = None,
    stable_polls_to_finish: int = 3,
) -> dict[str, Any]:
    """The LLM-agent-spawning flavor of the director — moved here verbatim
    from ``phase_supervisor.run_pipeline`` (plans/harness/09-dual-mode-
    planner.md Step 2: "phase_supervisor's driving loop folds into this
    directly"). Every helper it calls (``decide_actions``, ``_spawn_agent_job``,
    ``subagent_brief``, ``PipelineState``, …) stays in phase_supervisor.py
    unchanged and reused as-is — they're still the read-only status/brief
    machinery ``platform_pipeline`` depends on too; only the driving LOOP
    moved, so there is exactly one place that runs a full engagement
    autonomously (this module), not two.

    Drives the concurrent phase pipeline (recon always first, vuln/exploit
    spawn once ``priority.should_unlock_phase`` says there's real evidence)
    to fixpoint or the time budget. Non-blocking for callers that want fire-
    and-forget: wrap in ``asyncio.create_task``. The heavy work happens in
    the spawned agent and expansion jobs; this loop only decides + monitors.
    """
    from osprey.services import phase_supervisor, priority, sufficiency
    from osprey.services.phase_supervisor import (
        PipelineState,
        _active_by_phase,
        _expansion_running,
        _maybe_auto_scan_network_vulns,
        _reopen_signal,
        _spawn_agent_job,
        decide_actions,
        subagent_brief,
    )

    if not (engagement_id or "").strip():
        return {"error": "engagement_id required"}

    cfg = sufficiency.load_pipeline_config()
    poll = float(cfg.get("supervisor_poll_seconds") or 8)
    budget = float(cfg.get("pipeline_time_budget_seconds") or 3600)
    max_per_phase = int(cfg.get("max_agents_per_phase") or 3)
    reopen_types = sufficiency.recon_reopen_types()

    state = PipelineState(engagement_id=engagement_id, run_id=run_id)

    async def emit(event: str, data: dict[str, Any]) -> None:
        if on_event is None:
            return
        result = on_event(event, {**data, "engagement_id": engagement_id})
        if result is not None:
            await result

    # Kick off: the recon lead agent, not the deterministic breadth engine
    # too — see phase_supervisor.py's module docstring for why the two don't
    # both auto-start (same ground, same tools, would just race the shared
    # tool-execution cache instead of complementing each other).
    recon_job = _spawn_agent_job(
        engagement_id=engagement_id, run_id=run_id, role="recon", task=subagent_brief("recon"),
    )
    state.spawned_by_phase["recon"] = 1 if recon_job else 0
    await emit("pipeline_start", {"recon_job": recon_job})

    while True:
        await asyncio.sleep(poll)

        if time.monotonic() - state.started_at > budget:
            await emit("pipeline_stop", {"reason": "time_budget"})
            break

        signals = sufficiency.phase_signals(engagement_id)
        active = _active_by_phase(engagement_id)
        ctx = priority.build_context(engagement_id)
        phase_unlock = {
            phase: priority.should_unlock_phase(engagement_id, phase, ctx=ctx)
            for phase in phase_supervisor._DOWNSTREAM_PHASES
        }

        # 1) Trigger downstream phases (concurrent, additive).
        for action in decide_actions(
            phase_unlock=phase_unlock, active_by_phase=active,
            spawned_by_phase=state.spawned_by_phase, max_agents_per_phase=max_per_phase,
        ):
            if action.phase == "vuln":
                await _maybe_auto_scan_network_vulns(engagement_id=engagement_id, run_id=run_id)
            job_id = _spawn_agent_job(
                engagement_id=engagement_id, run_id=run_id, role=action.phase,
                task=f"{subagent_brief(action.phase)}\n\nContext: triggered because "
                     f"{action.reason}. Work the {action.phase} surface the earlier "
                     "phases discovered.",
            )
            if job_id:
                state.spawned_by_phase[action.phase] = state.spawned_by_phase.get(action.phase, 0) + 1
                state.triggered.add(action.phase)
                await emit("phase_triggered", {"phase": action.phase, "reason": action.reason, "job_id": job_id})

        # 2) Feedback: new host/subdomain findings while recon is idle → reopen recon.
        reopen_count = sum(signals.get(_reopen_signal(t), 0) for t in reopen_types)
        recon_active = active.get("recon", 0) > 0
        if (
            not recon_active
            and reopen_count > state.last_reopen_count
            and state.spawned_by_phase.get("recon", 0) < max_per_phase * 2
        ):
            job_id = _spawn_agent_job(
                engagement_id=engagement_id, run_id=run_id, role="recon",
                task=f"{subagent_brief('recon')}\n\nContext: new hosts/subdomains were "
                     "discovered by a later phase. Expand and probe these newly-surfaced assets.",
            )
            if job_id:
                state.spawned_by_phase["recon"] = state.spawned_by_phase.get("recon", 0) + 1
                await emit("recon_reopened", {"job_id": job_id, "reopen_count": reopen_count})
        state.last_reopen_count = reopen_count

        # 3) Fixpoint: no active agents AND no new findings for N stable polls.
        findings_total = sum(signals.values())
        any_active = bool(active) or _expansion_running(engagement_id)
        if not any_active and findings_total == state.last_findings_total:
            state.stable_polls += 1
        else:
            state.stable_polls = 0
        state.last_findings_total = findings_total

        await emit("pipeline_tick", {
            "signals": signals, "active": active,
            "spawned": dict(state.spawned_by_phase), "stable_polls": state.stable_polls,
        })

        if state.stable_polls >= stable_polls_to_finish:
            await emit("pipeline_stop", {"reason": "fixpoint"})
            break

    return {
        "engagement_id": engagement_id,
        "run_id": run_id,
        "spawned_by_phase": dict(state.spawned_by_phase),
        "triggered": sorted(state.triggered),
        "signals": sufficiency.phase_signals(engagement_id),
    }
