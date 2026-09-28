"""EXPANSION jobs (platform_expand — the primary recon/vuln engine) used to
update only the job's own progress/results_log fields, pull-style
(platform_job_poll). Nothing published to event_bus, so anything watching the
engagement's live activity stream (the CLI's own background listener,
GET /api/v1/agent/events/{id}) never saw background recon work happen — only
JobKind.AGENT jobs did. These prove the fix: an EXPANSION job's progress now
reaches event_bus, tagged source="expand". See
plans/harness/11-operator-trust-and-safety.md Step 3.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, patch

from osprey.schemas.jobs import JobKind, JobStartRequest
from osprey.services import event_bus
from osprey.services.job_store import get_job_store
from osprey.services.surface_expansion import ExpansionDelta


def _eid() -> str:
    return f"e-{uuid.uuid4().hex[:10]}"


async def _spawn_and_wait(req: JobStartRequest):
    store = get_job_store()
    summary = store.create_and_spawn(req)
    record = store._jobs[summary.job_id]  # test-only introspection
    assert record.task is not None
    await record.task
    return store, summary.job_id


def test_expansion_job_publishes_to_event_bus():
    eid = _eid()

    async def _fake_run_to_completion(*, engagement_id, run_id, max_passes, on_pass=None, on_progress=None, min_origin_confidence=0.0):
        if on_progress is not None:
            on_progress("live-host: web-depth probing example.com…")
            on_progress("RESULT::✓ live hosts: found 1 — example.com open")
        return ExpansionDelta(
            engagement_id=engagement_id, frontier_processed=1, new_nodes=1,
            new_edges=0, exhausted=True, total_passes=1,
        )

    published: list[tuple[str, str, dict]] = []
    orig_publish = event_bus.publish

    def _spy_publish(engagement_id, event, data, *, source=""):
        published.append((engagement_id, event, {**data, "_source": source}))
        return orig_publish(engagement_id, event, data, source=source)

    with patch(
        "osprey.services.investigation_director.run_to_completion",
        side_effect=_fake_run_to_completion,
    ), patch("osprey.services.event_bus.publish", side_effect=_spy_publish), \
       patch("osprey.services.mcp_client.get_mcp_client") as mock_mcp:
        mock_mcp.return_value.execution_status.return_value = {"mode": "native", "message": "native"}
        asyncio.run(_spawn_and_wait(
            JobStartRequest(kind=JobKind.EXPANSION, engagement_id=eid, max_passes=1)
        ))

    assert published, "EXPANSION job never published to event_bus"
    assert all(p[0] == eid for p in published)
    assert all(p[2]["_source"] == "expand" for p in published)
    result_events = [p for p in published if p[1] == "expand_result"]
    assert any("live hosts: found 1" in (e[2].get("message") or "") for e in result_events)


def test_expansion_job_still_updates_local_progress_for_job_poll():
    # The pre-existing pull-style contract (platform_job_poll reading
    # record.progress/results_log) must keep working unchanged alongside the
    # new event_bus push.
    eid = _eid()

    async def _fake_run_to_completion(*, engagement_id, run_id, max_passes, on_pass=None, on_progress=None, min_origin_confidence=0.0):
        if on_progress is not None:
            on_progress("RESULT::✓ subdomains: found 2 — a.example.com, b.example.com")
        return ExpansionDelta(
            engagement_id=engagement_id, frontier_processed=1, new_nodes=2,
            new_edges=2, exhausted=True, total_passes=1,
        )

    with patch(
        "osprey.services.investigation_director.run_to_completion",
        side_effect=_fake_run_to_completion,
    ), patch("osprey.services.mcp_client.get_mcp_client") as mock_mcp:
        mock_mcp.return_value.execution_status.return_value = {"mode": "native", "message": "native"}
        store, job_id = asyncio.run(_spawn_and_wait(
            JobStartRequest(kind=JobKind.EXPANSION, engagement_id=eid, max_passes=1)
        ))

    record = store._jobs[job_id]
    assert any("subdomains: found 2" in line for line in record.results_log)
