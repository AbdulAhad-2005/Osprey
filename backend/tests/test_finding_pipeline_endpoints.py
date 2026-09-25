"""REST surface for the earned-finding pipeline — plans/harness/03-earned-
finding-pipeline.md Step 3 (explicit filing) + Step 5 (deterministic
promotion). CLI-primacy invariant (plans/harness/README.md): every capability
drivable from the MCP layer must also work as a plain HTTP call, so this
tests the endpoints directly rather than only the Python functions.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from osprey.main import app
from osprey.schemas.observation import Observation, ObservationType
from osprey.services import fp_cache
from osprey.services.observation_store import get_observation_store


@pytest.fixture(autouse=True)
def _isolated_fp_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(fp_cache, "_FP_CACHE_DIR", tmp_path / "fp_cache")
    monkeypatch.setattr(fp_cache, "_PATTERNS_PATH", tmp_path / "fp_cache" / "patterns.jsonl")
    fp_cache.reload()
    yield
    fp_cache.reload()


def _make_engagement(target: str) -> str:
    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_file_finding_endpoint_computes_confidence_not_caller_provided():
    eid = _make_engagement("file-endpoint.test")
    # Observations are read-only over REST (GET /api/v1/observations/) — only
    # parsers/observation_engine create them (plans/harness/02-evidence-and-
    # observation-layer.md), so tests seed one via the store directly, same
    # as production ingest would.
    obs = get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="file-endpoint.test",
        source_tool="nuclei_scan", details={"claimed_severity": "high"},
    ))
    obs_id = obs.id
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/findings/file",
            json={
                "engagement_id": eid,
                "title": "Nuclei match, claiming critical",
                "finding_type": "vulnerability",
                "observation_ids": [obs_id],
                "claim_severity": "critical",
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["suppressed"] is False
        finding = data["finding"]
        assert finding["confidence"] == "hypothesis"  # no evidence_records attached — say-so ignored
        assert finding["claim_severity"] == "critical"  # severity is a separate, honestly-assigned axis
        assert finding["observation_ids"] == [obs_id]


def test_file_finding_endpoint_rejects_empty_observation_ids():
    eid = _make_engagement("file-endpoint-empty.test")
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/findings/file",
            json={
                "engagement_id": eid, "title": "X", "finding_type": "vulnerability",
                "observation_ids": [],
            },
        )
        assert resp.status_code == 422


def test_promote_endpoint_returns_findings_for_scanner_signals():
    eid = _make_engagement("promote-endpoint.test")
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="promote-endpoint.test",
        source_tool="nuclei_scan", details={"title": "CVE-2099-0003", "claimed_severity": "medium"},
    ))
    with TestClient(app) as client:
        resp = client.post("/api/v1/findings/promote", params={"engagement_id": eid})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["total"] == 1
        assert data["findings"][0]["confidence"] == "hypothesis"


def test_mark_false_positive_endpoint_retracts_and_lists_pattern():
    eid = _make_engagement("fp-endpoint.test")
    obs = get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="fp-endpoint.test",
        source_tool="nuclei_scan", details={"title": "Noisy match"},
    ))
    with TestClient(app) as client:
        file_resp = client.post(
            "/api/v1/findings/file",
            json={
                "engagement_id": eid, "title": "Noisy match", "finding_type": "vulnerability",
                "observation_ids": [obs.id],
            },
        )
        finding_id = file_resp.json()["finding"]["id"]

        fp_resp = client.post(f"/api/v1/findings/{finding_id}/fp", params={"reason": "confirmed noise"})
        assert fp_resp.status_code == 200, fp_resp.text
        assert fp_resp.json()["retracted_finding_id"] == finding_id

        list_resp = client.get("/api/v1/findings/fp/patterns")
        patterns = list_resp.json()["patterns"]
        assert len(patterns) == 1
        assert patterns[0]["reason"] == "confirmed noise"

        remove_resp = client.delete(f"/api/v1/findings/fp/patterns/{patterns[0]['id']}")
        assert remove_resp.status_code == 200
        assert client.get("/api/v1/findings/fp/patterns").json()["total"] == 0


def test_mark_false_positive_endpoint_404_for_unknown_finding():
    with TestClient(app) as client:
        resp = client.post("/api/v1/findings/does-not-exist/fp")
    assert resp.status_code == 404


def test_suppressed_promotions_audit_endpoint():
    eid = _make_engagement("fp-audit-endpoint.test")
    fp_cache.add_pattern(title_contains="always suppressed")
    obs = get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="fp-audit-endpoint.test",
        source_tool="nuclei_scan",
    ))
    with TestClient(app) as client:
        client.post(
            "/api/v1/findings/file",
            json={
                "engagement_id": eid, "title": "always suppressed signal",
                "finding_type": "vulnerability", "observation_ids": [obs.id],
            },
        )
        resp = client.get("/api/v1/findings/fp/suppressed", params={"engagement_id": eid})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
