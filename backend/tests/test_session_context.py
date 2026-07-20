"""Session bind — dynamic target → isolated engagement."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.services.run_store import get_run_store
from pentest_platform.services.session_context import bind_target, resolve_session


def test_resolve_reuses_latest_engagement_for_target() -> None:
    with TestClient(app) as client:
        a = client.post(
            "/api/v1/engagements/",
            json={"target": "bind-a.test", "name": "first"},
        ).json()
        b = client.post(
            "/api/v1/engagements/resolve",
            json={"target": "bind-a.test", "name": "second"},
        ).json()
    assert a["id"] == b["id"]
    assert b["reused"] is True


def test_resolve_creates_new_target() -> None:
    with TestClient(app) as client:
        data = client.post(
            "/api/v1/engagements/resolve",
            json={"target": "brand-new-dynamic.test"},
        ).json()
    assert data["created"] is True
    assert data["target"] == "brand-new-dynamic.test"


def test_bind_target_force_new() -> None:
    first = bind_target(seed_target="force-new.test", run_id="runforce00001")
    second = bind_target(
        seed_target="force-new.test",
        run_id="runforce00002",
        force_new=True,
    )
    assert first.engagement_id != second.engagement_id


def test_context_switch_target_changes_engagement() -> None:
    with TestClient(app) as client:
        a = client.post(
            "/api/v1/engagements/resolve",
            json={"target": "switch-a.test"},
        ).json()
        b = client.post(
            "/api/v1/engagements/resolve",
            json={"target": "switch-b.test"},
        ).json()
        resp = client.get(
            "/api/v1/hybrid/context/recon",
            params={"seed_target": "switch-b.test", "engagement_id": a["id"]},
        )
    assert resp.status_code == 200
    note = resp.json().get("note", "")
    assert "switch-b.test" in note or "switch" in note.lower()
    assert a["id"] != b["id"]


def test_context_requires_target_or_engagement() -> None:
    with TestClient(app) as client:
        resp = client.get("/api/v1/hybrid/context/recon")
    assert resp.status_code == 400


def test_tool_session_binds_run() -> None:
    session = bind_target(seed_target="bind-b.test", run_id="runbind12345")
    assert session.engagement_id
    assert get_run_store().get_engagement_id(run_id="runbind12345") == session.engagement_id
