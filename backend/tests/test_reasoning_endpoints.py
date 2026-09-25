"""World model + attack path + question + hypothesis REST surface —
plans/harness/05-world-model-and-attack-paths.md. CLI-primacy invariant
(plans/harness/README.md): every capability must be drivable as a plain HTTP
call, so this exercises the endpoints directly.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from osprey.main import app
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.observation_store import get_observation_store


def _make_engagement(target: str) -> str:
    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_assets_and_related_endpoints():
    eid = _make_engagement("reasoning-assets.test")
    get_engagement_graph().ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.PORT, target="reasoning-assets.test",
        details={"hostname": "reasoning-assets.test", "port": "80"},
    ))
    with TestClient(app) as client:
        resp = client.get("/api/v1/reasoning/assets", params={"engagement_id": eid, "asset_type": "host"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

        resp2 = client.get(
            "/api/v1/reasoning/related",
            params={"engagement_id": eid, "asset_id": "host:reasoning-assets.test"},
        )
        assert resp2.status_code == 200
        assert resp2.json()["total"] >= 1


def test_incomplete_and_unexplained_and_conflicts_endpoints():
    eid = _make_engagement("reasoning-gaps.test")
    get_engagement_graph().ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.HOST, target="reasoning-gaps.test",
        details={"hostname": "reasoning-gaps.test"},
    ))
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="reasoning-gaps.test",
        source_tool="nuclei_scan", details={"title": "signal"},
    ))
    with TestClient(app) as client:
        incomplete = client.get("/api/v1/reasoning/incomplete", params={"engagement_id": eid})
        assert incomplete.json()["total"] == 1

        unexplained = client.get("/api/v1/reasoning/unexplained", params={"engagement_id": eid})
        assert unexplained.json()["total"] == 1

        conflicts = client.get("/api/v1/reasoning/conflicts", params={"engagement_id": eid})
        assert conflicts.json()["total"] == 0


def test_attack_path_lifecycle_endpoint():
    eid = _make_engagement("reasoning-path.test")
    with TestClient(app) as client:
        create = client.post(
            "/api/v1/reasoning/attack-paths",
            json={
                "engagement_id": eid, "title": "public API -> internal ref",
                "steps": [{"kind": "observation", "ref_id": "obs1", "rationale": "found public API"}],
            },
        )
        assert create.status_code == 200, create.text
        path_id = create.json()["id"]
        assert create.json()["status"] == "hypothesized"

        advance = client.post(
            f"/api/v1/reasoning/attack-paths/{path_id}/advance",
            json={
                "status": "investigating",
                "step": {"kind": "observation", "ref_id": "obs2", "rationale": "cross-boundary ref"},
            },
        )
        assert advance.status_code == 200, advance.text
        assert advance.json()["status"] == "investigating"
        assert len(advance.json()["steps"]) == 2

        listing = client.get("/api/v1/reasoning/attack-paths", params={"engagement_id": eid})
        assert listing.json()["total"] == 1

        get_one = client.get(f"/api/v1/reasoning/attack-paths/{path_id}")
        assert get_one.status_code == 200


def test_attack_path_advance_404():
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/reasoning/attack-paths/does-not-exist/advance", json={"status": "dead"},
        )
    assert resp.status_code == 404


def test_question_lifecycle_endpoint():
    eid = _make_engagement("reasoning-question.test")
    with TestClient(app) as client:
        create = client.post(
            "/api/v1/reasoning/questions",
            params={"engagement_id": eid, "text": "Why does this host share an IP?"},
        )
        assert create.status_code == 200, create.text
        qid = create.json()["id"]

        answer = client.post(
            f"/api/v1/reasoning/questions/{qid}/answer", params={"answer_text": "Shared hosting."},
        )
        assert answer.status_code == 200
        assert answer.json()["status"] == "answered"

        listing = client.get("/api/v1/reasoning/questions", params={"engagement_id": eid, "open_only": False})
        assert listing.json()["total"] == 1


def test_hypothesis_lifecycle_endpoint():
    eid = _make_engagement("reasoning-hypothesis.test")
    with TestClient(app) as client:
        create = client.post(
            "/api/v1/reasoning/hypotheses",
            params={"engagement_id": eid, "statement": "Origin IP exposed behind CDN"},
        )
        assert create.status_code == 200, create.text
        hid = create.json()["id"]

        evidence = client.post(
            f"/api/v1/reasoning/hypotheses/{hid}/evidence",
            params={"observation_id": "obs1", "supports": True},
        )
        assert evidence.status_code == 200
        assert evidence.json()["supporting_observation_ids"] == ["obs1"]

        resolve = client.post(
            f"/api/v1/reasoning/hypotheses/{hid}/resolve", params={"status": "confirmed"},
        )
        assert resolve.status_code == 200
        assert resolve.json()["status"] == "confirmed"

        listing = client.get("/api/v1/reasoning/hypotheses", params={"engagement_id": eid, "active_only": False})
        assert listing.json()["total"] == 1
