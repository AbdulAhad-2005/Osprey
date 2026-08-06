"""Component 2 end-to-end: a wide port-range request through the real
/api/v1/mcp/execute path returns deferred + chunk job_ids, with no LLM
involved deciding to chunk it — proving the pre-flight interception actually
fires ahead of enforce_scan_budget, not after it.
"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from pentest_platform.main import app


def _make_engagement(client: TestClient, target: str) -> str:
    resp = client.post("/api/v1/engagements/", json={"target": target, "name": "chunk-dispatch-test"})
    return resp.json()["id"]


def test_moderately_wide_range_request_returns_deferred_with_chunk_jobs() -> None:
    # 1-3000 needs 3 chunks (1000 ports each) — deliberately kept well under
    # any reasonable concurrency cap (confirmed 4 in this environment) so
    # this test proves multi-chunk dispatch without being coupled to that
    # cap's exact tuned value. A request that needs MORE chunks than the cap
    # allows correctly triggers partial dispatch (see the cap-aware test
    # below) — that's the production code working as designed, not a bug.
    with TestClient(app) as client:
        eid = _make_engagement(client, "chunkdispatch1.test")
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "nmap_service_scan",
                "params": {"target": "chunkdispatch1.test", "ports": "1-3000"},
                "engagement_id": eid,
                "record_findings": False,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        recovery_info = data.get("recovery_info") or {}
        assert recovery_info.get("deferred") is True
        assert recovery_info.get("requested_chunk_count") == 3
        assert recovery_info.get("chunk_count") == 3
        assert len(recovery_info.get("job_ids") or []) == 3
        # Deferred means it never attempted the wide call as one shot —
        # no synchronous stdout from a real scan.
        assert data.get("stdout") == ""

        # The jobs are real — they show up in the job store immediately.
        time.sleep(0.2)
        jobs_resp = client.get("/api/v1/jobs", params={"engagement_id": eid})
        assert jobs_resp.status_code == 200
        job_ids_seen = {j["job_id"] for j in jobs_resp.json()}
        assert set(recovery_info["job_ids"]).issubset(job_ids_seen)


def test_range_exceeding_the_concurrency_cap_dispatches_partially_and_honestly() -> None:
    # Requesting more chunks than the live concurrency cap allows must queue
    # exactly as many as fit, report the true count (not the requested one),
    # and never silently drop the rest of the range without saying so.
    from pentest_platform.services.parallelism_config import max_running_jobs

    with TestClient(app) as client:
        eid = _make_engagement(client, "chunkdispatch4.test")
        cap = max_running_jobs()
        # Enough chunks to exceed the concurrency cap, but clamped to stay
        # within chunk_port_range's own _MAX_CHUNKS ceiling (8) — otherwise
        # in an environment tuned with a higher cap, this would ask for more
        # chunks than chunking allows at all, and the request would refuse
        # outright instead of partially dispatching.
        n_chunks_wanted = min(cap + 3, 7)
        if n_chunks_wanted <= cap:
            import pytest

            pytest.skip(f"concurrency cap ({cap}) too high relative to _MAX_CHUNKS to exercise partial dispatch")
        needed_ports = n_chunks_wanted * 1000
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "nmap_service_scan",
                "params": {"target": "chunkdispatch4.test", "ports": f"1-{needed_ports}"},
                "engagement_id": eid,
                "record_findings": False,
            },
        )
        assert resp.status_code == 200
        recovery_info = resp.json().get("recovery_info") or {}
        assert recovery_info.get("deferred") is True
        assert recovery_info["requested_chunk_count"] > recovery_info["chunk_count"]
        assert recovery_info["chunk_count"] == len(recovery_info["job_ids"])
        assert recovery_info["chunk_count"] >= 1


def test_full_range_request_still_refused_without_confirm_expensive() -> None:
    # A genuine full sweep needs more chunks than the safety ceiling allows —
    # chunk_port_range correctly declines, so this must fall through to the
    # existing refusal, unchanged by this feature.
    with TestClient(app) as client:
        eid = _make_engagement(client, "chunkdispatch2.test")
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "nmap_service_scan",
                "params": {"target": "chunkdispatch2.test", "ports": "1-65535"},
                "engagement_id": eid,
                "record_findings": False,
            },
        )
        assert resp.status_code == 400
        assert "confirm_expensive" in resp.json().get("detail", "").lower()


def test_narrow_range_request_runs_normally_not_deferred() -> None:
    # A request already within budget must not be touched by chunking at
    # all — same path as before this feature existed.
    with TestClient(app) as client:
        eid = _make_engagement(client, "chunkdispatch3.test")
        resp = client.post(
            "/api/v1/mcp/execute",
            json={
                "tool_name": "nmap_service_scan",
                "params": {"target": "chunkdispatch3.test", "ports": "1-100"},
                "engagement_id": eid,
                "record_findings": False,
            },
        )
        assert resp.status_code == 200
        recovery_info = resp.json().get("recovery_info") or {}
        assert recovery_info.get("deferred") is not True
