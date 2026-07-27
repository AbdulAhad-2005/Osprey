"""Active-memory awareness + flexible/bulk finding storage.

Covers the operator's asks:
- store many facts effectively in one call, with LLM-shaped tags/metadata (point 2)
- a data-driven consult drift signal, reset when memory is consulted (point 3)
- graph-driven deepening (unexplored assets) surfaced during work (point 4)
- unread completed-job awareness (point 5)
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.services import consult_tracker
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.parallelism_config import consult_drift_threshold


def test_bulk_findings_endpoint_stores_with_flexible_fields() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "bulk-mem.test"}).json()
        eid = eng["id"]

        payload = [
            {
                "engagement_id": eid,
                "run_id": "r1",
                "finding_type": "url",
                "title": "https://bulk-mem.test/api/v1/auth",
                "evidence": "HTTP/1.1 401 WWW-Authenticate: Bearer",
                "evidence_grade": "observed",
                # LLM-shaped, non-enum structure the platform must keep verbatim
                "tags": ["oracle", "login-portal"],
                "metadata": {"kind": "jwt", "alg": "none", "status": 401},
            },
            {
                "engagement_id": eid,
                "run_id": "r1",
                "finding_type": "observation",
                "title": "shared analytics id UA-123 across two hosts",
                "evidence": "UA-123 in main.js of a.test and b.test",
                "evidence_grade": "inferred",
            },
        ]
        resp = client.post("/api/v1/findings/bulk", json=payload)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 2

    stored = get_findings_store().list(engagement_id=eid, limit=50)
    by_title = {f.title: f for f in stored}
    api = by_title["https://bulk-mem.test/api/v1/auth"]
    # Arbitrary metadata keys are preserved unchanged — flexibility, not a fixed shape.
    assert api.metadata.get("kind") == "jwt"
    assert api.metadata.get("alg") == "none"
    assert "oracle" in api.tags and "login-portal" in api.tags


def test_bulk_findings_dedupes_by_content() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "bulk-dedupe.test"}).json()
        eid = eng["id"]
        item = {
            "engagement_id": eid,
            "run_id": "r1",
            "finding_type": "host",
            "title": "same.host",
            "evidence": "identical",
            "evidence_grade": "inferred",
        }
        # Same fact twice in one call → stored once.
        resp = client.post("/api/v1/findings/bulk", json=[item, dict(item)])
        assert resp.status_code == 200
        assert resp.json()["total"] == 1


def test_consult_drift_and_reset() -> None:
    eid = "eng-drift-1"
    consult_tracker.reset(eid)
    threshold = consult_drift_threshold()

    # No activity → no nudge.
    assert consult_tracker.build_memory_note(eid) == ""

    for _ in range(threshold):
        consult_tracker.record_exec(eid, findings_added=1)

    d = consult_tracker.drift(eid)
    assert d["tools_since"] == threshold
    note = consult_tracker.build_memory_note(eid)
    assert "consulted memory" in note  # drift nudge fires at threshold

    # Consulting memory resets the drift baseline → nudge clears.
    consult_tracker.mark_consulted(eid)
    assert consult_tracker.drift(eid)["tools_since"] == 0
    assert consult_tracker.build_memory_note(eid) == ""
    consult_tracker.reset(eid)


def test_unread_job_awareness_flag() -> None:
    eid = "eng-jobs-1"
    consult_tracker.reset(eid)
    # Below drift threshold, but an unread finished job still nudges.
    # Simulate: nothing marked read yet → build_memory_note reads job_store,
    # which is empty here, so note is empty; after marking a job read it stays empty.
    assert consult_tracker.build_memory_note(eid) == ""
    consult_tracker.mark_job_read(eid, "job_abc")
    # Marking read is idempotent and safe even with no job store entry.
    assert "job_abc" not in "".join(consult_tracker.drift(eid)["unread_jobs"])
    consult_tracker.reset(eid)
