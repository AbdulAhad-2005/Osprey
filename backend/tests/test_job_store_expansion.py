"""JobKind.EXPANSION — the BFS engine runs through the real background-job
dispatch mechanism (job_store.py's existing TOOL/SHELL/SCRIPT branch point),
not a bespoke blocking call. Covers progress reporting and the ExpansionReport
result shape (no .success attribute, unlike ToolExecutionResponse).
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, patch

from osprey.schemas.jobs import JobKind, JobStartRequest, JobStatus
from osprey.services.job_store import get_job_store
from osprey.services.surface_expansion import ExpansionDelta, ExpansionReport, PassReport


def _eid() -> str:
    return f"e-{uuid.uuid4().hex[:10]}"


def _report(exhausted=True, pass_count=2) -> ExpansionReport:
    passes = [
        PassReport(
            pass_number=i,
            delta=ExpansionDelta(
                engagement_id="x", frontier_processed=3, new_nodes=2, new_edges=1,
                exhausted=(i == pass_count and exhausted), total_passes=i,
            ),
            new_finding_titles=[f"new.host{i}.test"],
        )
        for i in range(1, pass_count + 1)
    ]
    return ExpansionReport(
        engagement_id="x", passes=passes, exhausted=exhausted,
        stopped_reason="exhausted" if exhausted else "max_passes",
    )


async def _spawn_and_wait(req: JobStartRequest):
    store = get_job_store()
    summary = store.create_and_spawn(req)
    # Find the record's task and await it directly so the test doesn't race
    # the background asyncio.Task the store spawned.
    record = store._jobs[summary.job_id]  # test-only introspection
    assert record.task is not None
    await record.task
    return store.get(summary.job_id), store.get_result(summary.job_id)


def test_expansion_job_completes_and_stores_report():
    eid = _eid()
    with patch(
        "osprey.services.investigation_director.run_to_completion",
        new_callable=AsyncMock,
    ) as mock_expand:
        mock_expand.return_value = _report()
        summary, result = asyncio.run(_spawn_and_wait(
            JobStartRequest(kind=JobKind.EXPANSION, engagement_id=eid, max_passes=5)
        ))
        assert summary.status == JobStatus.COMPLETED
        assert summary.kind == JobKind.EXPANSION
        assert result.result["exhausted"] is True
        assert "new.host1.test" in summary.finding_titles


def test_expansion_job_reports_progress_per_pass():
    eid = _eid()
    with patch(
        "osprey.services.investigation_director.run_to_completion",
        new_callable=AsyncMock,
    ) as mock_expand:
        async def _fake(*, engagement_id, run_id, max_passes, on_pass=None, on_progress=None, min_origin_confidence=None):
            report = _report(pass_count=3)
            for p in report.passes:
                if on_pass:
                    on_pass(p)
            return report
        mock_expand.side_effect = _fake

        async def _spawn_wait_and_get():
            store = get_job_store()
            summary = store.create_and_spawn(
                JobStartRequest(kind=JobKind.EXPANSION, engagement_id=eid, max_passes=5)
            )
            record = store._jobs[summary.job_id]
            await record.task
            return store.get(summary.job_id)

        final = asyncio.run(_spawn_wait_and_get())
        # Pass-boundary summaries are RESULT:: lines now — persistent in
        # results_log, not the ephemeral `progress` string.
        assert any("pass 3/5" in line for line in final.results_log)


def test_expansion_job_never_fails_from_internal_tool_errors():
    """run_expansion_pass already swallows per-tool failures internally — an
    ExpansionReport with no .success attribute reaching _run must still mark
    the job COMPLETED, not crash on attribute access."""
    eid = _eid()
    with patch(
        "osprey.services.investigation_director.run_to_completion",
        new_callable=AsyncMock,
    ) as mock_expand:
        mock_expand.return_value = _report(exhausted=False, pass_count=5)
        summary, _ = asyncio.run(_spawn_and_wait(
            JobStartRequest(kind=JobKind.EXPANSION, engagement_id=eid, max_passes=5)
        ))
        assert summary.status == JobStatus.COMPLETED
        assert summary.error == ""


def test_expansion_job_requires_no_tool_name_or_command():
    """Unlike TOOL/SHELL/SCRIPT, EXPANSION needs only engagement_id — must not
    raise the tool_name/command/code validation errors those kinds require."""
    eid = _eid()
    with patch(
        "osprey.services.investigation_director.run_to_completion",
        new_callable=AsyncMock,
    ) as mock_expand:
        mock_expand.return_value = _report()

        async def _spawn():
            return get_job_store().create_and_spawn(
                JobStartRequest(kind=JobKind.EXPANSION, engagement_id=eid)
            )

        summary = asyncio.run(_spawn())
        assert summary.status in (JobStatus.QUEUED, JobStatus.RUNNING)
