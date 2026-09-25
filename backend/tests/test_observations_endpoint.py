"""Observations REST API — the missing half of platform_file_finding: an
operator/LLM needs a way to discover observation_ids before it can file a
finding against one."""

from __future__ import annotations

from fastapi.testclient import TestClient

from osprey.main import app
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.observation_store import get_observation_store


def _make_engagement(target: str) -> str:
    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_list_observations_for_engagement():
    eid = _make_engagement("obs-endpoint.test")
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.PORT, target="obs-endpoint.test",
        source_tool="nmap_service_scan", details={"port": "443"},
    ))
    with TestClient(app) as client:
        resp = client.get("/api/v1/observations/", params={"engagement_id": eid})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["observations"][0]["type"] == "port"


def test_list_observations_filtered_by_type():
    eid = _make_engagement("obs-endpoint-type.test")
    store = get_observation_store()
    store.record(Observation(engagement_id=eid, type=ObservationType.PORT, target="x", details={"port": "80"}))
    store.record(Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="x", details={"title": "y"}))
    with TestClient(app) as client:
        resp = client.get("/api/v1/observations/", params={"engagement_id": eid, "type": "scanner_signal"})
    data = resp.json()
    assert data["total"] == 1
    assert data["observations"][0]["type"] == "scanner_signal"


def test_list_observations_rejects_unknown_type():
    eid = _make_engagement("obs-endpoint-bad-type.test")
    with TestClient(app) as client:
        resp = client.get("/api/v1/observations/", params={"engagement_id": eid, "type": "not_a_real_type"})
    assert resp.status_code == 422


def test_get_observation_by_id():
    eid = _make_engagement("obs-endpoint-get.test")
    obs = get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.HOST, target="obs-endpoint-get.test", details={"ip": "1.2.3.4"},
    ))
    with TestClient(app) as client:
        resp = client.get(f"/api/v1/observations/{obs.id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == obs.id


def test_get_observation_404_for_unknown_id():
    with TestClient(app) as client:
        resp = client.get("/api/v1/observations/does-not-exist")
    assert resp.status_code == 404


def test_record_observation_creates_llm_authored_observation():
    """The write path platform_record_finding routes through (plans/harness/
    03-earned-finding-pipeline.md gap-closing) — an LLM/operator fact with no
    parser behind it, never extracted_by=parser."""
    eid = _make_engagement("obs-write.test")
    with TestClient(app) as client:
        resp = client.post("/api/v1/observations/", json={
            "engagement_id": eid, "type": "raw",
            "target": "obs-write.test", "details": {"title": "IP-cluster grouping"},
            "source_tool": "operator_record", "tags": ["operator_recorded"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["engagement_id"] == eid
    assert data["extracted_by"] == "llm"
    assert data["type"] == "raw"


def test_record_observation_rejects_unknown_type():
    eid = _make_engagement("obs-write-bad-type.test")
    with TestClient(app) as client:
        resp = client.post("/api/v1/observations/", json={
            "engagement_id": eid, "type": "not_a_real_type", "target": "x",
        })
    assert resp.status_code == 422


def test_record_observation_rejects_bad_extracted_by():
    eid = _make_engagement("obs-write-bad-extractor.test")
    with TestClient(app) as client:
        resp = client.post("/api/v1/observations/", json={
            "engagement_id": eid, "type": "raw", "target": "x", "extracted_by": "parser",
        })
    assert resp.status_code == 422
