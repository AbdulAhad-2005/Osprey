"""Job persistence beyond kind=expansion.

Previously _persist_scan_run() early-returned for every kind except EXPANSION,
so a backend restart lost every AGENT job platform_pipeline/platform_spawn_agent
create (and every TOOL/SHELL/SCRIPT job) with no trace — platform_job_poll /
platform_job_result would just come back "unknown job". The durable table
(ScanRunStore/ScanRunRow) was already generic; only the artificial kind
restriction in job_store.py made it EXPANSION-only. These tests cover: (1) a
non-EXPANSION job actually gets a durable row, (2) get()/get_result() fall back
to that row once the in-memory record is gone (simulating a restart or a
_MAX_JOBS_KEPT prune), (3) an AGENT job's real success/failure — not just "the
loop returned" — decides its terminal JobStatus.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

from osprey.schemas.jobs import JobKind, JobStartRequest, JobStatus
from osprey.schemas.tools import ToolExecutionResponse
from osprey.services.job_store import get_job_store
from osprey.services.scan_run_store import get_scan_run_store


def _eid() -> str:
    return f"e-{uuid.uuid4().hex[:10]}"


async def _spawn_and_wait(req: JobStartRequest):
    store = get_job_store()
    summary = store.create_and_spawn(req)
    record = store._jobs[summary.job_id]  # test-only introspection
    assert record.task is not None
    await record.task
    return store, summary.job_id


def test_tool_job_persists_to_durable_store():
    eid = _eid()
    with patch(
        "osprey.services.tool_execution.execute_tool_request",
        new_callable=AsyncMock,
    ) as mock_exec:
        mock_exec.return_value = ToolExecutionResponse(
            tool_name="subfinder_scan", success=True, stdout="ok",
        )
        store, job_id = asyncio.run(_spawn_and_wait(
            JobStartRequest(kind=JobKind.TOOL, engagement_id=eid, tool_name="subfinder_scan", params={"domain": "example.com"})
        ))
        row = get_scan_run_store().get(job_id)
        assert row is not None
        assert row["kind"] == "tool"
        assert row["status"] == "completed"


def test_get_falls_back_to_durable_store_after_in_memory_record_is_gone():
    eid = _eid()
    with patch(
        "osprey.services.tool_execution.execute_tool_request",
        new_callable=AsyncMock,
    ) as mock_exec:
        mock_exec.return_value = ToolExecutionResponse(
            tool_name="subfinder_scan", success=True, stdout="ok", finding_titles=["sub.example.com"],
        )
        store, job_id = asyncio.run(_spawn_and_wait(
            JobStartRequest(kind=JobKind.TOOL, engagement_id=eid, tool_name="subfinder_scan", params={"domain": "example.com"})
        ))
        # Simulate a backend restart: the in-memory dict is gone, only the
        # durable row survives.
        with store._lock:
            del store._jobs[job_id]

        summary = store.get(job_id)
        assert summary is not None
        assert summary.status == JobStatus.COMPLETED
        assert summary.job_id == job_id

        result = store.get_result(job_id)
        assert result is not None
        assert result.job.status == JobStatus.COMPLETED


def test_get_returns_none_for_a_job_id_that_never_existed():
    store = get_job_store()
    assert store.get("job_does_not_exist") is None
    assert store.get_result("job_does_not_exist") is None


@dataclass
class _FakeAgentResponse:
    success: bool
    final_message: str = ""
    error: str = ""


def test_agent_job_failure_sets_failed_status_not_completed():
    """Reaching the end of the agent's run loop is NOT success — max_turns
    exceeded or an internal agent error must mark the job FAILED, the same
    way a failed ToolExecutionResponse does, not silently COMPLETED."""
    eid = _eid()
    with patch(
        "osprey.services.agent_runner.run_scoped_agent",
        new_callable=AsyncMock,
    ) as mock_agent, patch(
        "osprey.services.llm_service.llm_configured", return_value=True,
    ):
        mock_agent.return_value = _FakeAgentResponse(success=False, error="max_turns_exceeded")
        store, job_id = asyncio.run(_spawn_and_wait(
            JobStartRequest(kind=JobKind.AGENT, engagement_id=eid, role="recon", task="enumerate")
        ))
        summary = store.get(job_id)
        assert summary.status == JobStatus.FAILED
        assert "max_turns_exceeded" in summary.error


def test_agent_job_success_sets_completed_status():
    eid = _eid()
    with patch(
        "osprey.services.agent_runner.run_scoped_agent",
        new_callable=AsyncMock,
    ) as mock_agent, patch(
        "osprey.services.llm_service.llm_configured", return_value=True,
    ):
        mock_agent.return_value = _FakeAgentResponse(success=True, final_message="done")
        store, job_id = asyncio.run(_spawn_and_wait(
            JobStartRequest(kind=JobKind.AGENT, engagement_id=eid, role="recon", task="enumerate")
        ))
        summary = store.get(job_id)
        assert summary.status == JobStatus.COMPLETED
