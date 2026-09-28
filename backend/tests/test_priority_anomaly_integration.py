"""priority.py's unexplained_behavior factor now also reads anomaly_detection's
output — plans/harness/14-pentester-intelligence.md Step 1. A world-model
conflict and a peer statistical anomaly are two different sources feeding
the SAME factor.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from osprey.main import app
from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.observation import Observation, ObservationType
from osprey.services import priority
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.observation_store import get_observation_store


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def _make_engagement(target: str) -> str:
    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_unexplained_behavior_is_zero_with_no_anomaly():
    eid = _make_engagement("noanomaly.test")
    graph = get_engagement_graph()
    node = graph.ensure_node(engagement_id=eid, asset_type=AssetType.HOST, label="clean.noanomaly.test")

    ctx = priority.build_context(eid)
    score = priority.score_asset(node, ctx)
    assert score.factors.unexplained_behavior == 0.0


def test_unexplained_behavior_is_one_for_a_host_with_an_anomaly_observation():
    eid = _make_engagement("hasanomaly.test")
    graph = get_engagement_graph()
    node = graph.ensure_node(engagement_id=eid, asset_type=AssetType.HOST, label="odd.hasanomaly.test")
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="odd.hasanomaly.test",
        source_tool="anomaly_detection",
        details={"title": "synthetic anomaly for test", "kind": "timing_outlier"},
        tags=["anomaly", "timing_outlier"],
    ))

    ctx = priority.build_context(eid)
    score = priority.score_asset(node, ctx)
    assert score.factors.unexplained_behavior == 1.0


def test_unexplained_behavior_unaffected_for_a_sibling_host_without_the_anomaly_tag():
    eid = _make_engagement("sibling.test")
    graph = get_engagement_graph()
    odd_node = graph.ensure_node(engagement_id=eid, asset_type=AssetType.HOST, label="odd.sibling.test")
    clean_node = graph.ensure_node(engagement_id=eid, asset_type=AssetType.HOST, label="clean.sibling.test")
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="odd.sibling.test",
        source_tool="anomaly_detection",
        details={"title": "synthetic anomaly for test", "kind": "timing_outlier"},
        tags=["anomaly", "timing_outlier"],
    ))

    ctx = priority.build_context(eid)
    assert priority.score_asset(odd_node, ctx).factors.unexplained_behavior == 1.0
    assert priority.score_asset(clean_node, ctx).factors.unexplained_behavior == 0.0


def test_anomalies_endpoint_returns_real_detected_anomalies():
    from osprey.services.evidence_store import get_evidence_store

    eid = _make_engagement("endpoint.test")
    store = get_evidence_store()
    for label in ("a", "b", "c", "d"):
        store.record(engagement_id=eid, tool_name="httpx_probe", target=f"{label}.endpoint.test", duration_ms=100)
    store.record(engagement_id=eid, tool_name="httpx_probe", target="slow.endpoint.test", duration_ms=9000)

    with TestClient(app) as client:
        resp = client.get("/api/v1/priority/anomalies", params={"engagement_id": eid})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["count"] >= 1
        assert any(a["target"] == "slow.endpoint.test" for a in data["anomalies"])
