"""job_store.py's "already scheduled" duplicate-admission guard used to
block JobStatus.COMPLETED as well as QUEUED/RUNNING — meaning ANY
investigation-step opportunity whose tool call had ever failed became
PERMANENTLY unrunnable for the rest of that job record's life: list_step()
correctly keeps a failed opportunity's id eligible (only a SUCCESSFUL
completion excludes it via _successful_opportunity_ids), the deterministic
driver would legitimately re-decide the same opportunity, and this guard
silently 409'd every single retry forever. Observed live as an endless
"Evidence changed before scheduling; replanning." loop that hit on whichever
tool happened to fail first (dnsenum_scan, gau_discovery, domain_hunter —
never the same one twice), until the CLI's retry cap gave up.

A genuinely-completed-SUCCESSFUL opportunity was never actually protected by
the COMPLETED branch of this guard in the first place — it's already absent
from list_step()'s own opportunity list by the time create_and_spawn() looks
it up, so the earlier "investigation opportunity is not current" check
rejects it first. Only a FAILED opportunity's retry was ever affected.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.jobs import JobKind, JobStartRequest
from osprey.schemas.tools import ToolExecutionResponse
from osprey.services import investigation_capabilities, tool_execution
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.job_store import get_job_store


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_a_failed_opportunity_can_be_retried_immediately():
    eid = _make_engagement("retry-after-fail.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="retry-after-fail.test",
    )
    store = get_job_store()

    step0 = investigation_capabilities.list_step(eid)
    opp = next(o for o in step0.opportunities if o.tool)

    async def _run_first_attempt():
        fail_response = ToolExecutionResponse(tool_name=opp.tool, success=False, stdout="", error="502")
        with patch.object(
            tool_execution, "get_mcp_client",
            return_value=type("M", (), {"call_tool": AsyncMock(return_value=fail_response)})(),
        ):
            summary = store.create_and_spawn(JobStartRequest(
                kind=JobKind.INVESTIGATION_STEP, engagement_id=eid,
                capability=opp.capability.value, tool=opp.tool, params=dict(opp.params),
                opportunity_id=opp.id, subject_ids=[s.asset_id for s in opp.subjects],
                expected_revision=step0.revision,
            ))
            await store._jobs[summary.job_id].task
        return summary

    summary1 = asyncio.run(_run_first_attempt())

    assert store.get(summary1.job_id).status.value == "completed"
    assert store.get(summary1.job_id).success is False

    # The same opportunity id must still be offered (its tool call failed —
    # it's not "done") and must be re-admittable, not permanently blocked by
    # the first attempt's own now-COMPLETED job record.
    step1 = investigation_capabilities.list_step(eid)
    retry_opp = next((o for o in step1.opportunities if o.id == opp.id), None)
    assert retry_opp is not None, "a failed opportunity must stay eligible for retry"

    async def _retry():
        return store.create_and_spawn(JobStartRequest(
            kind=JobKind.INVESTIGATION_STEP, engagement_id=eid,
            capability=retry_opp.capability.value, tool=retry_opp.tool, params=dict(retry_opp.params),
            opportunity_id=retry_opp.id, subject_ids=[s.asset_id for s in retry_opp.subjects],
            expected_revision=step1.revision,
        ))

    summary2 = asyncio.run(_retry())
    assert summary2.job_id != summary1.job_id


def test_a_genuinely_in_flight_duplicate_is_still_rejected():
    """The guard must still catch a real concurrent double-submission —
    only COMPLETED was ever wrongly included, QUEUED/RUNNING stay blocked."""
    eid = _make_engagement("still-blocks-inflight.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="still-blocks-inflight.test",
    )
    store = get_job_store()
    step0 = investigation_capabilities.list_step(eid)
    opp = next(o for o in step0.opportunities if o.tool)

    async def _run():
        hang = asyncio.Event()

        async def _never_returns(*_a, **_kw):
            await hang.wait()
            return ToolExecutionResponse(tool_name=opp.tool, success=True, stdout="ok")

        with patch.object(
            tool_execution, "get_mcp_client",
            return_value=type("M", (), {"call_tool": _never_returns})(),
        ):
            first = store.create_and_spawn(JobStartRequest(
                kind=JobKind.INVESTIGATION_STEP, engagement_id=eid,
                capability=opp.capability.value, tool=opp.tool, params=dict(opp.params),
                opportunity_id=opp.id, subject_ids=[s.asset_id for s in opp.subjects],
                expected_revision=step0.revision,
            ))
            # Re-sense: admitting the first job itself changes active_jobs,
            # so a second attempt using the stale step0.revision would be
            # correctly rejected by the (unrelated) revision check before
            # ever reaching the duplicate-opportunity guard this test targets.
            step_after_first = investigation_capabilities.list_step(eid)
            try:
                store.create_and_spawn(JobStartRequest(
                    kind=JobKind.INVESTIGATION_STEP, engagement_id=eid,
                    capability=opp.capability.value, tool=opp.tool, params=dict(opp.params),
                    opportunity_id=opp.id, subject_ids=[s.asset_id for s in opp.subjects],
                    expected_revision=step_after_first.revision,
                ))
                raised = False
            except ValueError as exc:
                raised = "already scheduled" in str(exc)
            finally:
                hang.set()
                await store._jobs[first.job_id].task
        return raised

    assert asyncio.run(_run()), "a still-QUEUED/RUNNING duplicate must still be rejected"


def test_an_always_failing_opportunity_stops_being_offered_after_the_cap():
    """The complement of test_a_failed_opportunity_can_be_retried_immediately:
    one failure stays retryable, but an opportunity that keeps failing
    (gau_discovery timing out against unreachable external services, observed
    live as an endless re-pick loop) must stop being offered after
    _MAX_OPPORTUNITY_FAILURES so the deterministic driver moves on instead of
    retrying the identical action forever."""
    eid = _make_engagement("always-fails.test")
    get_engagement_graph().ensure_node(
        engagement_id=eid, asset_type=AssetType.DOMAIN, label="always-fails.test",
    )
    store = get_job_store()

    step = investigation_capabilities.list_step(eid)
    opp = next(o for o in step.opportunities if o.tool)

    async def _fail_once(revision: str):
        fail_response = ToolExecutionResponse(tool_name=opp.tool, success=False, stdout="", error="502")
        with patch.object(
            tool_execution, "get_mcp_client",
            return_value=type("M", (), {"call_tool": AsyncMock(return_value=fail_response)})(),
        ):
            summary = store.create_and_spawn(JobStartRequest(
                kind=JobKind.INVESTIGATION_STEP, engagement_id=eid,
                capability=opp.capability.value, tool=opp.tool, params=dict(opp.params),
                opportunity_id=opp.id, subject_ids=[s.asset_id for s in opp.subjects],
                expected_revision=revision,
            ))
            await store._jobs[summary.job_id].task

    # First failure: still eligible (1 < _MAX_OPPORTUNITY_FAILURES).
    asyncio.run(_fail_once(step.revision))
    step_after_1 = investigation_capabilities.list_step(eid)
    assert any(o.id == opp.id for o in step_after_1.opportunities), "one failure must stay retryable"

    # Second failure hits the cap: the identical opportunity is no longer offered.
    asyncio.run(_fail_once(step_after_1.revision))
    step_after_2 = investigation_capabilities.list_step(eid)
    assert not any(o.id == opp.id for o in step_after_2.opportunities), (
        "an opportunity that failed _MAX_OPPORTUNITY_FAILURES times must stop being offered"
    )
    assert opp.id in investigation_capabilities._failed_opportunity_ids(eid)
