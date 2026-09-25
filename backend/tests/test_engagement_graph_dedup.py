"""Regression test for the DOMAIN/SUBDOMAIN duplicate-node bug: a hostname
already tracked as a SUBDOMAIN must not also get a parallel DOMAIN "seed"
skeleton node when it's later used as the `target` of a recursively-found
subdomain — that duplicate never gets an `expanded` flag and permanently
re-enters surface_expansion.py's discovery frontier every pass.

Uses ``ingest_observation`` — the primary graph builder since plans/harness/
05-world-model-and-attack-paths.md Step 1 (``ingest_finding`` now only stamps
a filed Finding's link to a node its own observations already built; it mints
no structure itself).
"""

from __future__ import annotations

import uuid

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.engagement_graph import get_engagement_graph


def _eid() -> str:
    # engagement_id is VARCHAR(12) in the schema (matches real engagement ids
    # like "3dabdbfb91c6") — anything longer silently fails the insert.
    return uuid.uuid4().hex[:12]


def test_subdomain_used_as_target_does_not_spawn_duplicate_domain_node():
    eid = _eid()
    graph = get_engagement_graph()

    # apnegn.geo.tv is first discovered as a SUBDOMAIN of geo.tv (normal path).
    graph.ingest_observation(
        Observation(
            engagement_id=eid, type=ObservationType.SUBDOMAIN,
            target="geo.tv", details={"hostname": "apnegn.geo.tv"},
        )
    )
    # Then apnegn.geo.tv itself gets re-scanned (it's a valid discovery
    # target) and a recursive discovery tool finds a subdomain under it.
    graph.ingest_observation(
        Observation(
            engagement_id=eid, type=ObservationType.SUBDOMAIN,
            target="apnegn.geo.tv", details={"hostname": "mx.apnegn.geo.tv"},
        )
    )

    domain_dupes = graph.list_nodes(engagement_id=eid, asset_type=AssetType.DOMAIN, limit=200)
    assert not any(n.label == "apnegn.geo.tv" for n in domain_dupes), (
        "apnegn.geo.tv must not exist as a second DOMAIN-typed node — "
        "it should reuse the existing SUBDOMAIN node for lineage edges"
    )

    subdomains = graph.list_nodes(engagement_id=eid, asset_type=AssetType.SUBDOMAIN, limit=200)
    assert any(n.label == "apnegn.geo.tv" for n in subdomains)
    assert any(n.label == "mx.apnegn.geo.tv" for n in subdomains)

    edges = graph.list_edges(engagement_id=eid, limit=200)
    subdomain_of_edges = [e for e in edges if e.relationship == "subdomain_of"]
    # mx.apnegn.geo.tv -> subdomain_of -> the SUBDOMAIN node for apnegn.geo.tv
    assert any(
        e.target_id == "subdomain:apnegn.geo.tv" for e in subdomain_of_edges
    ), [e.target_id for e in subdomain_of_edges]
    # Every edge cites the observation that asserted it (Step 1 done criterion).
    assert all(e.observation_ids for e in subdomain_of_edges)


def test_genuinely_new_sister_domain_still_gets_a_seed_domain_node():
    """A sister domain that ISN'T already tracked as a subdomain must still
    get its normal DOMAIN seed node — the fix must not suppress legitimate
    new-domain creation, only the duplicate case."""
    eid = _eid()
    graph = get_engagement_graph()

    graph.ingest_observation(
        Observation(
            engagement_id=eid, type=ObservationType.SUBDOMAIN,
            target="geo-news.tv", details={"hostname": "portal.geo-news.tv"},
        )
    )

    domain_nodes = graph.list_nodes(engagement_id=eid, asset_type=AssetType.DOMAIN, limit=200)
    assert any(n.label == "geo-news.tv" for n in domain_nodes)


def test_every_node_and_edge_cites_an_observation_id():
    """plans/harness/05-world-model-and-attack-paths.md Step 1 done criterion:
    every graph edge/node the deterministic builder creates carries evidence."""
    eid = _eid()
    graph = get_engagement_graph()
    obs = Observation(
        engagement_id=eid, type=ObservationType.PORT, target="scan-target.test",
        source_tool="nmap_service_scan", details={"hostname": "scan-target.test", "port": "443"},
    )
    graph.ingest_observation(obs)

    nodes = graph.list_nodes(engagement_id=eid, limit=200)
    assert nodes
    for n in nodes:
        assert n.observation_ids, f"node {n.id} has no observation backing it"

    edges = graph.list_edges(engagement_id=eid, limit=200)
    assert edges
    for e in edges:
        assert e.observation_ids, f"edge {e.source_id}->{e.target_id} has no observation backing it"


def test_node_confidence_rises_with_independent_corroboration():
    eid = _eid()
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.HOST, target="corroborated.test",
        source_tool="dnsx_resolve", details={"hostname": "corroborated.test"},
    ))
    nodes = graph.list_nodes(engagement_id=eid, asset_type=AssetType.HOST, limit=10)
    host = next(n for n in nodes if n.label == "corroborated.test")
    assert host.confidence == "hypothesis"
    assert host.source_tools == ["dnsx_resolve"]

    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.HOST, target="corroborated.test",
        source_tool="shodan_search", details={"hostname": "corroborated.test"},
    ))
    nodes = graph.list_nodes(engagement_id=eid, asset_type=AssetType.HOST, limit=10)
    host = next(n for n in nodes if n.label == "corroborated.test")
    assert host.confidence == "likely"
    assert set(host.source_tools) == {"dnsx_resolve", "shodan_search"}


def test_conflicting_service_observations_kept_not_overwritten():
    """plans/harness/05-world-model-and-attack-paths.md Step 2a: two tools
    disagreeing on service@443 keeps both values, marks the slot conflicted,
    never silently picks one."""
    eid = _eid()
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.SERVICE, target="conflict-host.test",
        source_tool="nmap_service_scan",
        details={"hostname": "conflict-host.test", "port": "443", "service": "nginx"},
    ))
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.SERVICE, target="conflict-host.test",
        source_tool="whatweb_scan",
        details={"hostname": "conflict-host.test", "port": "443", "service": "Apache"},
    ))

    ports = graph.list_nodes(engagement_id=eid, asset_type=AssetType.PORT, limit=10)
    port_node = next(n for n in ports if n.label == "conflict-host.test:443")
    assert "service" in port_node.conflicts
    values = {c.value.lower() for c in port_node.conflicts["service"]}
    assert values == {"nginx", "apache"}
    # A disputed slot is never silently resolved to one value in metadata.
    assert "service" not in port_node.metadata


def test_conflicting_slot_accumulates_a_third_value_without_resolving():
    """Once a slot is disputed, it stays disputed — a third distinct value
    must join the conflict set, not silently "win" because the two-value
    prior_value comparison came up empty on this round."""
    eid = _eid()
    graph = get_engagement_graph()
    for tool, svc in (("nmap_service_scan", "nginx"), ("whatweb_scan", "Apache"), ("wappalyzer_scan", "IIS")):
        graph.ingest_observation(Observation(
            engagement_id=eid, type=ObservationType.SERVICE, target="triple-conflict.test",
            source_tool=tool,
            details={"hostname": "triple-conflict.test", "port": "443", "service": svc},
        ))
    ports = graph.list_nodes(engagement_id=eid, asset_type=AssetType.PORT, limit=10)
    port_node = next(n for n in ports if n.label == "triple-conflict.test:443")
    values = {c.value.lower() for c in port_node.conflicts["service"]}
    assert values == {"nginx", "apache", "iis"}
    assert "service" not in port_node.metadata
