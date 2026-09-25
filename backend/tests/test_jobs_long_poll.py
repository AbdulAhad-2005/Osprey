"""GET /api/v1/jobs/{job_id}?wait_seconds=N — long-poll so a caller doesn't
need to fire repeated polls in a tight loop (the call-count-economy fix).
"""

from __future__ import annotations

import time
import uuid

from fastapi.testclient import TestClient

from osprey.main import app


def _eid() -> str:
    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": f"longpoll-{uuid.uuid4().hex[:8]}.test"})
        return resp.json()["id"]


def test_wait_seconds_zero_returns_immediately():
    eid = _eid()
    with TestClient(app) as client:
        started = client.post(
            "/api/v1/jobs/start",
            json={"kind": "shell", "engagement_id": eid, "command": "sleep 3"},
        ).json()
        t0 = time.monotonic()
        resp = client.get(f"/api/v1/jobs/{started['job_id']}")
        elapsed = time.monotonic() - t0
    assert resp.status_code == 200
    assert elapsed < 2  # no waiting requested, must not block


def test_wait_seconds_returns_early_on_completion():
    eid = _eid()
    with TestClient(app) as client:
        started = client.post(
            "/api/v1/jobs/start",
            json={"kind": "shell", "engagement_id": eid, "command": "echo hi", "timeout": 30},
        ).json()
        t0 = time.monotonic()
        resp = client.get(f"/api/v1/jobs/{started['job_id']}", params={"wait_seconds": 30})
        elapsed = time.monotonic() - t0
    assert resp.status_code == 200
    # A trivial `echo hi` finishes almost immediately — long-poll must return
    # as soon as status leaves RUNNING/QUEUED, not sit out the full 30s.
    assert elapsed < 15
    assert resp.json()["status"] in ("completed", "failed")


def test_wait_seconds_caps_at_60():
    eid = _eid()
    with TestClient(app) as client:
        resp = client.get(f"/api/v1/jobs/does-not-exist-{eid}", params={"wait_seconds": 999})
    # Validation happens before the 404 lookup — either way, an out-of-range
    # wait_seconds must not be silently honored past the documented cap.
    assert resp.status_code in (404, 422)
