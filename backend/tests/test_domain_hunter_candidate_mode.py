"""domain_hunter storage is mode-aware: the deterministic engine's own
mechanical dispatch (caller="deterministic_engine") stores sisters directly
(confirmed graph nodes); any other caller — an LLM's typed-tool call, or an
operator driving the tool directly — gets candidates for a human/LLM to
validate and promote, not auto-promoted sister nodes.

This is a request-scoped signal (the ``caller`` kwarg threaded from
investigation_capabilities._execute_tool), not a global "is an LLM key
configured anywhere" check — that global check used to decide this and was
wrong: a backend with a key configured for other sessions would silently
orphan a deterministic-engine run's sisters as unreviewed candidates
forever, regardless of who/what actually drove this specific call."""

from __future__ import annotations

import json

from osprey.schemas.engagement_graph import AssetType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.parsers.recon_network.subdomains import parse_domain_hunter

_STDOUT = (
    '# DHJSON '
    + json.dumps([{"domain": "sister-co.net", "method": "reverse_whois",
                   "confidence": "high", "live": True, "score": 40,
                   "evidence": ["same WHOIS registrant/org as seed-co.test"]}])
)


def _eid() -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        return client.post("/api/v1/engagements/", json={"target": "seed-co.test"}).json()["id"]


def test_deterministic_mode_stores_confirmed_sister():
    obs = parse_domain_hunter(_STDOUT, engagement_id="e1", target="seed-co.test", caller="deterministic_engine")
    assert obs and obs[0].details["role"] == "sister_domain" and "sister_domain" in obs[0].tags


def test_direct_call_marks_candidate():
    obs = parse_domain_hunter(_STDOUT, engagement_id="e1", target="seed-co.test")
    assert obs and obs[0].details["role"] == "sister_candidate" and "sister_candidate" in obs[0].tags


def test_an_llm_key_being_configured_elsewhere_does_not_flip_deterministic_mode(monkeypatch):
    """The old bug: role used to hinge on the GLOBAL llm_configured() check,
    so a backend with a key configured for unrelated sessions would wrongly
    demote the deterministic engine's own run to candidate-mode. Now it must
    stay confirmed regardless of that global state."""
    monkeypatch.setattr("osprey.services.llm_service.llm_configured", lambda: True)
    obs = parse_domain_hunter(_STDOUT, engagement_id="e1", target="seed-co.test", caller="deterministic_engine")
    assert obs and obs[0].details["role"] == "sister_domain"


def test_candidate_is_not_promoted_to_a_graph_node():
    eid = _eid()
    graph = get_engagement_graph()
    for obs in parse_domain_hunter(_STDOUT, engagement_id=eid, target="seed-co.test"):
        graph.ingest_observation(obs)
    nodes = [n for t in (AssetType.DOMAIN, AssetType.HOST, AssetType.SUBDOMAIN)
             for n in graph.list_nodes(engagement_id=eid, asset_type=t, limit=50)]
    assert not any(n.label == "sister-co.net" for n in nodes), "candidate wrongly became a graph node"


def test_deterministic_sister_becomes_a_graph_node():
    eid = _eid()
    graph = get_engagement_graph()
    for obs in parse_domain_hunter(_STDOUT, engagement_id=eid, target="seed-co.test", caller="deterministic_engine"):
        graph.ingest_observation(obs)
    nodes = [n for t in (AssetType.DOMAIN, AssetType.HOST, AssetType.SUBDOMAIN)
             for n in graph.list_nodes(engagement_id=eid, asset_type=t, limit=50)]
    node = next((n for n in nodes if n.label == "sister-co.net"), None)
    assert node is not None and node.metadata.get("role") == "sister_domain"
