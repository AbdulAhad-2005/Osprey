"""Re-feed a Recording through the *real*, current ingestion pipeline — no
live tool execution, no network — and read back what it produced.

This is the whole point of the ruler: it reuses the exact same
``extract_observations_for_execution`` + ``apply_ingest_rules`` call sequence
``tool_execution.py`` makes on every real tool run (see that file's call site
this mirrors), against a disposable scratch engagement, so changing a parser
or the finding pipeline in Plans 02-04 is measurable in seconds without
touching a single live tool. Since Plan 02, this reads back Observations
(the tool-execution path no longer creates Findings — see
plans/harness/02-evidence-and-observation-layer.md); ``findings`` stays on
``ReplayResult`` for Plan 03, when ``promote_observations``/
``platform_file_finding`` start writing there again.
"""

from __future__ import annotations

import logging
import uuid

from osprey.schemas.benchmark import Recording, ReplayResult
from osprey.schemas.engagement import EngagementCreateRequest
from osprey.schemas.tools import ToolExecutionResponse
from osprey.services.engagement_store import get_engagement_store
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store

logger = logging.getLogger(__name__)

_REPLAY_RUN_ID = "replay"


async def _ingest_one(call, *, engagement_id: str, allow_llm_fallback: bool) -> None:
    """The exact ingestion call sequence tool_execution.py makes for a real
    tool run (see tool_execution.py's `record_findings` block) — replayed
    against the scratch engagement instead of the original one."""
    from osprey.services.ingest_promoter import apply_ingest_rules
    from osprey.services.summary_agent import extract_observations_for_execution

    response = ToolExecutionResponse(
        tool_name=call.tool_name,
        success=call.success,
        command=call.command,
        returncode=call.returncode,
        stdout=call.stdout,
        stderr=call.stderr,
        timed_out=call.timed_out,
        duration_seconds=call.duration_seconds,
    )
    await extract_observations_for_execution(
        response,
        engagement_id=engagement_id,
        run_id=_REPLAY_RUN_ID,
        target=call.target,
        allow_llm_fallback=allow_llm_fallback,
    )
    apply_ingest_rules(
        response.stdout or "",
        response.stderr or "",
        engagement_id=engagement_id,
        run_id=_REPLAY_RUN_ID,
        source_tool=call.tool_name,
        target=call.target,
        persist=True,
    )


async def replay_recording(
    recording: Recording, *, cleanup: bool = True, live_llm: bool = False
) -> ReplayResult:
    """Create a scratch engagement, replay every call through real ingestion,
    read back what it produced (observations, plus any findings — empty on
    the tool-execution path until Plan 03's promotion pipeline lands), then
    discard the scratch engagement (cascade-deletes findings/observations/
    graph/coverage — see EngagementStore.delete).

    Deterministic by default (``live_llm=False``): the LLM structural-
    extraction fallback inside the ingestion pipeline is disabled for this
    replay, so the result never depends on whether an LLM happens to be
    configured in the replaying process — see
    plans/harness/01-replay-benchmark-harness.md's "Determinism scope". Pass
    ``live_llm=True`` to measure with it on (then treat the result as a
    distribution over repeated runs, not one number).
    """
    store = get_engagement_store()
    scratch_target = f"benchmark-replay-{uuid.uuid4().hex[:10]}.invalid"
    engagement = store.create(EngagementCreateRequest(target=scratch_target, name=f"replay:{recording.name}"))

    try:
        for call in recording.calls:
            try:
                await _ingest_one(call, engagement_id=engagement.id, allow_llm_fallback=live_llm)
            except Exception as exc:  # noqa: BLE001 — one bad record shouldn't kill the replay
                logger.warning("replay: ingest failed for %s: %s", call.tool_name, exc)

        findings = get_findings_store().list(engagement_id=engagement.id, run_id=None, limit=5000)
        observations = get_observation_store().list_for_engagement(engagement.id)
        result = ReplayResult(
            fixture_name=recording.name,
            scratch_engagement_id=engagement.id,
            findings=[f.model_dump(mode="json") for f in findings],
            observations=[o.model_dump(mode="json") for o in observations],
            calls_replayed=len(recording.calls),
            live_llm=live_llm,
        )
    finally:
        if cleanup:
            store.delete(engagement.id)

    return result
