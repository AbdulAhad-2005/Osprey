"""world_model — plans/harness/05-world-model-and-attack-paths.md Step 2."""

from __future__ import annotations

import uuid

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.observation import Observation, ObservationType
from osprey.services import world_model
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.observation_store import get_observation_store


def _eid() -> str:
    return uuid.uuid4().hex[:12]


def test_assets_filters_by_type():
    eid = _eid()
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.HOST, target="wm-assets.test",
        details={"hostname": "wm-assets.test"},
    ))
    hosts = world_model.assets(eid, AssetType.HOST)
    assert any(n.label == "wm-assets.test" for n in hosts)
    ports = world_model.assets(eid, AssetType.PORT)
    assert ports == []


def test_related_returns_multi_hop_neighbors():
    eid = _eid()
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.PORT, target="wm-related.test",
        details={"hostname": "wm-related.test", "port": "22"},
    ))
    result = world_model.related(eid, "host:wm-related.test", max_hops=1)
    assert any(r["node_id"] == "port:wm-related.test:22" for r in result)


def test_assets_with_incomplete_investigation_flags_hosts_without_ports():
    eid = _eid()
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.HOST, target="wm-incomplete.test",
        details={"hostname": "wm-incomplete.test"},
    ))
    gaps = world_model.assets_with_incomplete_investigation(eid)
    assert any(g["asset_id"] == "host:wm-incomplete.test" for g in gaps)


def test_assets_with_incomplete_investigation_excludes_hosts_with_ports():
    eid = _eid()
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.PORT, target="wm-complete.test",
        details={"hostname": "wm-complete.test", "port": "443"},
    ))
    gaps = world_model.assets_with_incomplete_investigation(eid)
    assert not any(g["asset_id"] == "host:wm-complete.test" for g in gaps)


def test_unexplained_observations_returns_facts_with_no_graph_node():
    eid = _eid()
    store = get_observation_store()
    # SCANNER_SIGNAL never builds graph structure — always unexplained until
    # a hypothesis/attack-path cites it.
    obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="wm-unexplained.test",
        source_tool="nuclei_scan", details={"title": "some signal"},
    ))
    unexplained = world_model.unexplained_observations(eid)
    assert any(o["observation_id"] == obs.id for o in unexplained)


def test_explained_observations_are_excluded():
    eid = _eid()
    graph = get_engagement_graph()
    store = get_observation_store()
    obs = store.record(Observation(
        engagement_id=eid, type=ObservationType.HOST, target="wm-explained.test",
        details={"hostname": "wm-explained.test"},
    ))
    graph.ingest_observation(obs)
    unexplained = world_model.unexplained_observations(eid)
    assert not any(o["observation_id"] == obs.id for o in unexplained)


def test_conflicts_surfaces_disputed_slots():
    eid = _eid()
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.SERVICE, target="wm-conflict.test",
        source_tool="nmap_service_scan",
        details={"hostname": "wm-conflict.test", "port": "443", "service": "nginx"},
    ))
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.SERVICE, target="wm-conflict.test",
        source_tool="whatweb_scan",
        details={"hostname": "wm-conflict.test", "port": "443", "service": "Apache"},
    ))
    disputed = world_model.conflicts(eid)
    assert any(c["asset_id"] == "port:wm-conflict.test:443" for c in disputed)
