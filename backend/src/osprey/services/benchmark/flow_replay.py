"""Flow replay — drive the REAL decision loop, not just ingestion.

``replay.py`` answers "what did ingestion produce from this recorded output?".
This module answers the different question plan 19 Phase 1 needs:

    "Given target state, what tool calls does the engine DECIDE to make —
     does the deterministic floor actually reach nuclei / sqlmap?"

It drives the exact production decision path the no-LLM CLI harness drives:
``investigation_capabilities.list_step`` (the backend's opportunity computation)
+ ``DeterministicInvestigationDriver``'s selection rule (max priority), executing
each chosen opportunity by replaying its recorded stdout through the same
ingestion ``tool_execution`` uses — no live tools, no network, no LLM. The result
is a ``FlowTrace``: every capability the engine OFFERED and every one it EXECUTED,
to a fixpoint. That trace is the ruler for "did the flow reach vuln analysis".

Determinism: ingestion runs with the LLM structural-extraction fallback OFF
(``allow_llm_fallback=False``), same as ``replay.replay_recording``'s default, so
the trace depends only on the engine's rules and the recorded corpus.
"""

from __future__ import annotations

import logging
import uuid

from osprey.schemas.benchmark import FlowTrace, Recording
from osprey.schemas.engagement import EngagementCreateRequest
from osprey.services.benchmark.replay import _ingest_one
from osprey.services.engagement_store import get_engagement_store

logger = logging.getLogger(__name__)

_FLOW_RUN_ID = "flow-replay"


def _opportunity_target(opp) -> str:
    """The asset an opportunity acts on — the value the recorded corpus is keyed
    by. Prefer an explicit subject label; fall back to any param value that
    looks like a host/URL (params carry the node label under target/domain/ip/
    url depending on the tool, so match on the values, not a fixed key)."""
    for subj in getattr(opp, "subjects", None) or []:
        label = getattr(subj, "label", "") or (subj.get("label") if isinstance(subj, dict) else "")
        if label:
            return str(label)
    for v in (getattr(opp, "params", None) or {}).values():
        if isinstance(v, str) and v.strip():
            return v.strip().splitlines()[0]
    return ""


def _corpus_index(recording: Recording) -> dict[tuple[str, str], object]:
    """(tool_name, target) -> ToolCallRecord, for opportunity lookup."""
    idx: dict[tuple[str, str], object] = {}
    for call in recording.calls:
        idx[(call.tool_name, call.target)] = call
    return idx


async def run_flow_to_fixpoint(
    recording: Recording,
    *,
    seed_target: str = "",
    max_steps: int = 200,
    cleanup: bool = True,
) -> FlowTrace:
    """Drive ``list_step`` -> pick max-priority -> replay its recorded output ->
    re-sense, until no offered opportunity has a matching recorded output (the
    fixpoint this corpus can reach) or ``max_steps`` is hit.

    Returns a FlowTrace recording the union of offered capabilities and the
    ordered sequence of executed ones. ``seed_target`` overrides the
    recording's own target for the scratch engagement (default: recording.target).
    """
    from osprey.services.investigation_capabilities import list_step

    store = get_engagement_store()
    target = seed_target or recording.target or f"flow-{uuid.uuid4().hex[:8]}.invalid"
    engagement = store.create(EngagementCreateRequest(target=target, name=f"flow:{recording.name}"))
    eid = engagement.id
    corpus = _corpus_index(recording)

    offered: set[tuple[str, str]] = set()
    executed: list[tuple[str, str]] = []
    executed_ids: set[str] = set()
    steps = 0

    try:
        while steps < max_steps:
            steps += 1
            step = list_step(eid, run_id=_FLOW_RUN_ID)
            live = [o for o in step.opportunities if getattr(o, "id", "")]
            for o in live:
                offered.add((o.tool, _opportunity_target(o)))
            if not live:
                break
            # Deterministic driver's exact rule: highest priority first. Then
            # take the highest-priority one we actually have recorded output for
            # and haven't already run (so the corpus drives progress, and an
            # offered-but-uncorpused capability is recorded as offered without
            # stalling the loop).
            runnable = [
                o for o in sorted(live, key=lambda x: -x.priority)
                if o.id not in executed_ids and (o.tool, _opportunity_target(o)) in corpus
            ]
            if not runnable:
                break
            chosen = runnable[0]
            tgt = _opportunity_target(chosen)
            await _ingest_one(corpus[(chosen.tool, tgt)], engagement_id=eid, allow_llm_fallback=False)
            executed.append((chosen.tool, tgt))
            executed_ids.add(chosen.id)

        return FlowTrace(
            fixture_name=recording.name,
            scratch_engagement_id=eid,
            seed_target=target,
            offered=sorted(f"{t}@{a}" for (t, a) in offered),
            executed=[f"{t}@{a}" for (t, a) in executed],
            steps=steps,
            reached_fixpoint=steps < max_steps,
        )
    finally:
        if cleanup:
            store.delete(eid)


async def offered_after_ingest(recording: Recording, *, seed_target: str = "") -> FlowTrace:
    """Sharper single-shot variant: ingest the WHOLE corpus once (build state),
    then ask ``list_step`` what it offers — no selection loop. Use this to assert
    a direct state->capability contract ("live web host present => nuclei offered")
    without needing a full multi-hop corpus that reaches the state by execution."""
    from osprey.services.investigation_capabilities import list_step

    store = get_engagement_store()
    target = seed_target or recording.target or f"flow-{uuid.uuid4().hex[:8]}.invalid"
    engagement = store.create(EngagementCreateRequest(target=target, name=f"flow1:{recording.name}"))
    eid = engagement.id
    try:
        for call in recording.calls:
            await _ingest_one(call, engagement_id=eid, allow_llm_fallback=False)
        step = list_step(eid, run_id=_FLOW_RUN_ID)
        offered = sorted(
            f"{o.tool}@{_opportunity_target(o)}" for o in step.opportunities if getattr(o, "id", "")
        )
        return FlowTrace(
            fixture_name=recording.name,
            scratch_engagement_id=eid,
            seed_target=target,
            offered=offered,
            executed=[],
            steps=1,
            reached_fixpoint=True,
        )
    finally:
        store.delete(eid)
