"""JobKind.AGENT — a backend-auto-executed phase agent must be genuinely
watchable turn-by-turn (platform_job_poll), not fire-and-forget. Mirrors the
EXPANSION job's proven progress/results_log pattern: tool_end/assistant/
phase_done/error events land as persistent RESULT:: entries in results_log;
tool_start/status are ephemeral `progress` (overwritten each call).
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, patch

from osprey.schemas.jobs import JobKind, JobStartRequest, JobStatus
from osprey.services.agent_common import AgentResponse
from osprey.services.job_store import get_job_store


def _eid() -> str:
    return f"e-{uuid.uuid4().hex[:10]}"


def _llm_configured_true():
    """AGENT-kind create_and_spawn gates on llm_configured() (imported locally
    inside job_store.py, from llm_service — patch it at its source) — patch it
    True so these tests exercise the progress-wiring logic in isolation,
    independent of whatever LLM (if any) is actually configured in the running
    environment."""
    return patch("osprey.services.llm_service.llm_configured", return_value=True)


async def _spawn_and_wait(req: JobStartRequest):
    store = get_job_store()
    summary = store.create_and_spawn(req)
    record = store._jobs[summary.job_id]  # test-only introspection
    assert record.task is not None
    await record.task
    return store.get(summary.job_id)


def test_agent_job_tool_end_lands_in_persistent_results_log():
    eid = _eid()

    async def _fake_run_scoped_agent(*, engagement_id, run_id, role, task, scope, max_turns, on_event):
        await on_event("tool_start", {"tool_name": "subfinder_scan"})
        await on_event(
            "tool_end",
            {"tool_name": "subfinder_scan", "success": True, "preview": "found 12 subdomains"},
        )
        await on_event("phase_done", {"success": True, "tool_calls": 1})
        return AgentResponse(success=True, final_message="done", phase=role)

    with _llm_configured_true(), patch(
        "osprey.services.agent_runner.run_scoped_agent",
        new_callable=AsyncMock,
        side_effect=_fake_run_scoped_agent,
    ):
        final = asyncio.run(
            _spawn_and_wait(
                JobStartRequest(kind=JobKind.AGENT, engagement_id=eid, role="recon", task="enumerate")
            )
        )

    assert final.status == JobStatus.COMPLETED
    # Persistent history — survives after the job finishes, not just the last line.
    assert any("subfinder_scan" in line and "ok" in line for line in final.results_log)
    assert any("phase done" in line for line in final.results_log)


def test_agent_job_error_event_lands_in_results_log():
    eid = _eid()

    async def _fake_run_scoped_agent(*, engagement_id, run_id, role, task, scope, max_turns, on_event):
        await on_event("error", {"message": "Tool execution error: boom"})
        return AgentResponse(success=False, final_message="failed", phase=role, error="boom")

    with _llm_configured_true(), patch(
        "osprey.services.agent_runner.run_scoped_agent",
        new_callable=AsyncMock,
        side_effect=_fake_run_scoped_agent,
    ):
        final = asyncio.run(
            _spawn_and_wait(
                JobStartRequest(kind=JobKind.AGENT, engagement_id=eid, role="recon", task="enumerate")
            )
        )

    assert final.status == JobStatus.FAILED
    assert any("ERROR" in line and "boom" in line for line in final.results_log)


def test_agent_job_tool_start_is_ephemeral_progress_not_results_log():
    eid = _eid()

    async def _fake_run_scoped_agent(*, engagement_id, run_id, role, task, scope, max_turns, on_event):
        await on_event("tool_start", {"tool_name": "naabu_port_scan"})
        return AgentResponse(success=True, final_message="done", phase=role)

    with _llm_configured_true(), patch(
        "osprey.services.agent_runner.run_scoped_agent",
        new_callable=AsyncMock,
        side_effect=_fake_run_scoped_agent,
    ):
        final = asyncio.run(
            _spawn_and_wait(
                JobStartRequest(kind=JobKind.AGENT, engagement_id=eid, role="recon", task="enumerate")
            )
        )

    # tool_start is a "what's happening now" line, not a permanent history entry.
    assert not any("naabu_port_scan" in line for line in final.results_log)
