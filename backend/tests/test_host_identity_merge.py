"""Plan 19 — one canonical node identity per real hostname.

CONFIRMED BUG (found by querying a live engagement's persisted graph, not
guessed): subfinder enumerates a host as a SUBDOMAIN node
(``subdomain:live.geo.tv``); httpx_probe/naabu/dnsx then independently create
a SEPARATE ``host:live.geo.tv`` node for the exact same real host, because six
call sites in ``engagement_graph.ingest_observation`` hardcoded
``AssetType.HOST`` instead of reusing whatever node already represents that
label. Both nodes independently qualify for the full recon/host-expansion
battery (naabu/nuclei/rustscan/tech_stack/...), so every real host that gets
touched by both subdomain enumeration AND any URL/port/service/tech
observation — i.e. almost every host in a real engagement — silently runs its
entire pipeline TWICE under two different identities. This is the actual
cause of "tools looping back on the same things" (naabu ran 7-8x, nuclei 5-6x
on a single real host in one operator run).

Fix: one canonical helper (``_host_node``, reusing the already-correct
``_existing_or_guess_host_type``) used at every hostname-only call site.
"""
from __future__ import annotations

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.engagement_store import get_engagement_store


def _make_engagement(target: str) -> str:
    return get_engagement_store().create(EngagementCreateRequest(target=target)).id


def _node_labels_and_types(eid: str, label: str) -> list[tuple[str, str]]:
    nodes = get_engagement_graph().list_nodes(engagement_id=eid, limit=1000)
    return sorted((n.asset_type.value, n.label) for n in nodes if n.label == label)


def test_subdomain_then_url_observation_collapse_to_one_node():
    """The exact real-world sequence that created the split identity: subfinder
    enumerates the subdomain, THEN httpx_probe reports a URL on that same host."""
    eid = _make_engagement("geo.tv")
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.SUBDOMAIN, target="geo.tv",
        source_tool="subfinder_scan", details={"hostname": "live.geo.tv"},
    ))
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.URL, target="https://live.geo.tv",
        source_tool="httpx_probe", details={"url": "https://live.geo.tv"},
    ))

    nodes = _node_labels_and_types(eid, "live.geo.tv")
    assert nodes == [("subdomain", "live.geo.tv")], (
        f"expected exactly one SUBDOMAIN node for live.geo.tv, got: {nodes}"
    )


def test_url_then_subdomain_observation_still_collapse_to_one_node():
    """Order-independent: if the URL/host observation lands FIRST (a real
    possibility depending on scheduling), the later subdomain enumeration must
    still converge onto one node, not fork a second."""
    eid = _make_engagement("geo.tv")
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.PORT, target="live.geo.tv",
        source_tool="naabu_port_scan", details={"hostname": "live.geo.tv", "port": "80"},
    ))
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.SUBDOMAIN, target="geo.tv",
        source_tool="subfinder_scan", details={"hostname": "live.geo.tv"},
    ))

    # The PORT observation alone (before subdomain enum ever runs) has no
    # existing subdomain/domain node to reuse yet, so _existing_or_guess_host_type
    # correctly infers SUBDOMAIN from label depth (not a generic HOST default) —
    # and the later real subdomain enumeration then reuses that same node.
    nodes = _node_labels_and_types(eid, "live.geo.tv")
    assert nodes == [("subdomain", "live.geo.tv")], (
        f"expected exactly one SUBDOMAIN node for live.geo.tv, got: {nodes}"
    )


def test_technology_and_service_observations_reuse_the_same_host_node():
    """TECHNOLOGY and SERVICE observations (two more of the six fixed sites)
    must also converge on the subdomain node already created for this host."""
    eid = _make_engagement("geo.tv")
    graph = get_engagement_graph()
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.SUBDOMAIN, target="geo.tv",
        source_tool="subfinder_scan", details={"hostname": "www.geo.tv"},
    ))
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.TECHNOLOGY, target="https://www.geo.tv",
        source_tool="tech_stack_analyze", details={"name": "nginx", "hostname": "www.geo.tv"},
    ))
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.SERVICE, target="www.geo.tv",
        source_tool="nmap_service_scan", details={"hostname": "www.geo.tv", "port": "443", "service": "https"},
    ))

    nodes = _node_labels_and_types(eid, "www.geo.tv")
    assert nodes == [("subdomain", "www.geo.tv")], (
        f"expected exactly one SUBDOMAIN node for www.geo.tv, got: {nodes}"
    )


def test_apex_domain_already_a_domain_node_is_not_forked_into_a_host():
    """A HOST-type observation (e.g. a sister/origin host) for a label already
    tracked as the apex DOMAIN must reuse the domain node, not fork a host:
    twin for the seed domain itself."""
    eid = _make_engagement("geo.tv")
    graph = get_engagement_graph()
    graph.ensure_node(engagement_id=eid, asset_type=AssetType.DOMAIN, label="geo.tv")
    graph.ingest_observation(Observation(
        engagement_id=eid, type=ObservationType.HOST, target="geo.tv",
        source_tool="domain_hunter", details={"hostname": "geo.tv"},
    ))

    nodes = _node_labels_and_types(eid, "geo.tv")
    assert nodes == [("domain", "geo.tv")], f"expected exactly one DOMAIN node for geo.tv, got: {nodes}"
