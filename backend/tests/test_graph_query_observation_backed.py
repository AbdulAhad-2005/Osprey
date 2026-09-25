"""graph_query surfaces observation-backed nodes/edges — plans/harness/05-
world-model-and-attack-paths.md Reconnect: "graph_query MCP tool now returns
observation-backed nodes/edges + attack paths."
"""

from __future__ import annotations

import uuid

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.graph_query import query_graph


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def test_query_graph_nodes_carry_observation_ids_and_confidence():
    eid = _eid()
    graph = get_engagement_graph()
    obs = Observation(
        engagement_id=eid, type=ObservationType.PORT, target="gq-obs-backed.test",
        source_tool="nmap_service_scan", details={"hostname": "gq-obs-backed.test", "port": "22"},
    )
    graph.ingest_observation(obs)

    result = query_graph(eid, asset_type="host")
    assert result["count"] == 1
    node = result["nodes"][0]
    assert node["observation_ids"] == [obs.id]
    assert node["confidence"] == "hypothesis"


def test_query_graph_edges_carry_observation_ids():
    eid = _eid()
    graph = get_engagement_graph()
    obs = Observation(
        engagement_id=eid, type=ObservationType.PORT, target="gq-edge-backed.test",
        source_tool="nmap_service_scan", details={"hostname": "gq-edge-backed.test", "port": "22"},
    )
    graph.ingest_observation(obs)

    result = query_graph(eid, asset_type="host")
    assert result["edges"]
    for e in result["edges"]:
        assert e["observation_ids"], f"edge {e} has no observation backing"


def test_query_graph_multi_hop_nodes_carry_observation_ids():
    eid = _eid()
    graph = get_engagement_graph()
    obs = Observation(
        engagement_id=eid, type=ObservationType.PORT, target="gq-multihop.test",
        details={"hostname": "gq-multihop.test", "port": "443"},
    )
    graph.ingest_observation(obs)

    result = query_graph(eid, from_asset="host:gq-multihop.test", max_hops=1)
    assert result["nodes"]
    assert all("observation_ids" in n for n in result["nodes"])
