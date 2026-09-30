"""The dashboard page must render for a bound engagement and point its
EventSource at the real, already-existing live stream endpoint — no new
event-plumbing duplicated client-side."""

from __future__ import annotations

from fastapi.testclient import TestClient

from osprey.main import app


def test_dashboard_page_renders_with_engagement_and_target():
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "dashboard-page.test"}).json()
        eid = eng["id"]

        resp = client.get(f"/api/v1/dashboard/{eid}")

    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert eid in resp.text
    assert "dashboard-page.test" in resp.text
    assert "/api/v1/agent/events/" in resp.text


def test_dashboard_page_renders_even_for_an_unknown_engagement_id():
    with TestClient(app) as client:
        resp = client.get("/api/v1/dashboard/does-not-exist")

    assert resp.status_code == 200
    assert "does-not-exist" in resp.text
