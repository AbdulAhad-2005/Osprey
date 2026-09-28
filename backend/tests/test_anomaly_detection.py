"""Peer-anomaly detection — plans/harness/14-pentester-intelligence.md Step 1.

Deterministic, no LLM: a host running much slower than its siblings on the
same tool, or an older version of the same product its siblings run.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from osprey.main import app
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.anomaly_detection import detect_peer_anomalies
from osprey.services.evidence_store import get_evidence_store
from osprey.services.observation_store import get_observation_store


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def _make_engagement(target: str) -> str:
    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_no_anomaly_below_minimum_peer_group():
    eid = _make_engagement("thin.test")
    store = get_evidence_store()
    store.record(engagement_id=eid, tool_name="httpx_probe", target="a.thin.test", duration_ms=100)
    store.record(engagement_id=eid, tool_name="httpx_probe", target="b.thin.test", duration_ms=9000)
    # Only 2 peers — below _MIN_PEER_GROUP, must not flag anything.
    assert detect_peer_anomalies(eid) == []


def test_timing_outlier_flagged_among_real_peer_group():
    eid = _make_engagement("peers.test")
    store = get_evidence_store()
    for label in ("a", "b", "c", "d"):
        store.record(engagement_id=eid, tool_name="httpx_probe", target=f"{label}.peers.test", duration_ms=100)
    store.record(engagement_id=eid, tool_name="httpx_probe", target="slow.peers.test", duration_ms=9000)

    results = detect_peer_anomalies(eid)
    flagged_targets = {o.target for o in results if o.details.get("kind") == "timing_outlier"}
    assert "slow.peers.test" in flagged_targets
    assert "a.peers.test" not in flagged_targets


def test_timing_not_flagged_when_all_peers_uniform():
    eid = _make_engagement("uniform.test")
    store = get_evidence_store()
    for label in ("a", "b", "c", "d", "e"):
        store.record(engagement_id=eid, tool_name="nmap_service_scan", target=f"{label}.uniform.test", duration_ms=500)
    assert detect_peer_anomalies(eid) == []


def test_version_drift_flagged_among_real_peer_group():
    eid = _make_engagement("versions.test")
    obs_store = get_observation_store()
    for label in ("a", "b", "c", "d"):
        obs_store.record(Observation(
            engagement_id=eid, type=ObservationType.TECHNOLOGY, target=f"{label}.versions.test",
            source_tool="httpx_probe", details={"name": "nginx", "version": "1.25.3"},
        ))
    obs_store.record(Observation(
        engagement_id=eid, type=ObservationType.TECHNOLOGY, target="old.versions.test",
        source_tool="httpx_probe", details={"name": "nginx", "version": "1.14.0"},
    ))

    results = detect_peer_anomalies(eid)
    drift = [o for o in results if o.details.get("kind") == "version_drift"]
    assert any(o.target == "old.versions.test" for o in drift)
    assert not any(o.target == "a.versions.test" for o in drift)


def test_version_not_flagged_when_no_real_majority():
    eid = _make_engagement("scattered.test")
    obs_store = get_observation_store()
    versions = ["1.1.0", "1.2.0", "1.3.0", "1.4.0"]
    for label, ver in zip("abcd", versions):
        obs_store.record(Observation(
            engagement_id=eid, type=ObservationType.TECHNOLOGY, target=f"{label}.scattered.test",
            source_tool="httpx_probe", details={"name": "custom-app", "version": ver},
        ))
    # Every peer runs a distinct version — no stable majority, nothing to
    # call "drift" against.
    results = detect_peer_anomalies(eid)
    assert not any(o.details.get("kind") == "version_drift" for o in results)


def test_detect_peer_anomalies_is_idempotent_no_duplicate_rows():
    eid = _make_engagement("idempotent.test")
    store = get_evidence_store()
    for label in ("a", "b", "c", "d"):
        store.record(engagement_id=eid, tool_name="httpx_probe", target=f"{label}.idempotent.test", duration_ms=100)
    store.record(engagement_id=eid, tool_name="httpx_probe", target="slow.idempotent.test", duration_ms=9000)

    first = detect_peer_anomalies(eid)
    second = detect_peer_anomalies(eid)
    all_obs = get_observation_store().list_for_engagement(eid, limit=1000)
    timing_obs = [o for o in all_obs if o.details.get("kind") == "timing_outlier" and o.target == "slow.idempotent.test"]
    assert len(timing_obs) == 1
    assert first and second
