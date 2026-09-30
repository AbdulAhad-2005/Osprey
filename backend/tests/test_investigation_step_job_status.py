"""An INVESTIGATION_STEP job's own execution succeeding (execute_capability
returns instead of raising) must terminal-mark the job COMPLETED even when
the capability's underlying tool call itself reported success=False.

Before this fix, job_store.py mapped CapabilityResult.success straight onto
JobStatus (FAILED on a failed tool), which made the CLI's InvestigationDriver
treat one ordinary, expected recon hiccup (a crt.sh 502, a timed-out scan) as
a FATAL error and abandon the entire deterministic investigation — every
remaining opportunity silently dropped. A single tool's pass/fail is already
carried faithfully on the CapabilityResult and rendered per-opportunity (see
scan_shared.py's _run_investigation_events); it must never also decide
whether the driver's loop itself keeps going.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.jobs import JobKind, JobStartRequest, JobStatus
from osprey.schemas.tools import ToolExecutionResponse
from osprey.services import investigation_capabilities
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.job_store import get_job_store


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def _real_tool_opportunity(eid: str, target: str):
    get_engagement_graph().ensure_node(engagement_id=eid, asset_type=AssetType.DOMAIN, label=target)
    step = investigation_capabilities.list_step(eid)
    opp = next(o for o in step.opportunities if o.tool)
    return step.revision, opp


async def _spawn_and_wait(req: JobStartRequest):
    store = get_job_store()
    summary = store.create_and_spawn(req)
    record = store._jobs[summary.job_id]  # test-only introspection
    assert record.task is not None
    await record.task
    return store, summary.job_id


def test_investigation_step_job_completes_even_when_the_tool_call_failed():
    eid = _make_engagement("job-status-failed-tool.test")
    revision, opp = _real_tool_opportunity(eid, "job-status-failed-tool.test")

    with patch(
        "osprey.services.tool_execution.get_mcp_client",
        return_value=type("M", (), {"call_tool": AsyncMock(return_value=ToolExecutionResponse(
            tool_name=opp.tool, success=False, stdout="", error="upstream 502",
        ))})(),
    ):
        store, job_id = asyncio.run(_spawn_and_wait(JobStartRequest(
            kind=JobKind.INVESTIGATION_STEP, engagement_id=eid,
            capability=opp.capability.value, tool=opp.tool, params=dict(opp.params),
            opportunity_id=opp.id, subject_ids=[s.asset_id for s in opp.subjects],
            expected_revision=revision,
        )))
        summary = store.get(job_id)

    assert summary.status == JobStatus.COMPLETED, (
        "a failed tool call inside a capability must not fail the JOB — only "
        "a raised exception (a real execution failure) should"
    )
    assert "one_or_more_tools_failed" in (summary.error or "")


def test_investigation_step_job_still_fails_on_a_real_exception():
    eid = _make_engagement("job-status-real-exception.test")
    revision, opp = _real_tool_opportunity(eid, "job-status-real-exception.test")

    with patch(
        "osprey.services.investigation_capabilities.execute_capability",
        new_callable=AsyncMock, side_effect=RuntimeError("boom"),
    ):
        store, job_id = asyncio.run(_spawn_and_wait(JobStartRequest(
            kind=JobKind.INVESTIGATION_STEP, engagement_id=eid,
            capability=opp.capability.value, tool=opp.tool, params=dict(opp.params),
            opportunity_id=opp.id, subject_ids=[s.asset_id for s in opp.subjects],
            expected_revision=revision,
        )))
        summary = store.get(job_id)

    assert summary.status == JobStatus.FAILED
    assert "boom" in (summary.error or "")
