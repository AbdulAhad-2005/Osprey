"""World model — plans/harness/05-world-model-and-attack-paths.md Step 2.

A read model over the engagement graph + observation store answering the
questions the planner/LLM actually need — not a new store. Every answer here
is derived live from ``engagement_graph``/``observation_store`` state, so it
reflects whatever ``ingest_observation`` has built so far, including
conflicts (Step 2a) and confidence that can fall as well as rise (Step 1).
"""

from __future__ import annotations

from typing import Any

from osprey.schemas.engagement_graph import AssetNode, AssetType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.observation_store import get_observation_store


def assets(engagement_id: str, asset_type: AssetType | str | None = None, *, limit: int = 5000) -> list[AssetNode]:
    """Every asset node of a type (or all types) — a thin, named entry point
    over ``list_nodes`` so callers don't need to know the graph's own API."""
    return get_engagement_graph().list_nodes(engagement_id=engagement_id, asset_type=asset_type, limit=limit)


def related(engagement_id: str, asset_id: str, *, max_hops: int = 2, limit: int = 200) -> list[dict[str, Any]]:
    """What connects to this asset, closest first — an undirected walk of the
    graph (see ``find_paths_multi_hop``), the same way a human pentester
    follows relationships regardless of which way an edge was recorded."""
    return get_engagement_graph().find_paths_multi_hop(
        engagement_id=engagement_id, start_node_id=asset_id, max_hops=max_hops, limit=limit,
    )


def assets_with_incomplete_investigation(
    engagement_id: str, *, limit: int = 200
) -> list[dict[str, Any]]:
    """HOST/SUBDOMAIN assets with no port evidence yet — the base coverage
    check every other gap builds on. A narrower, queryable form of what
    ``EngagementGraph.summary()`` already computes ad hoc for its pivot
    hints; Plan 06 widens this into full coverage scoring over the world
    model instead of finding counts.
    """
    graph = get_engagement_graph()
    nodes = graph.list_nodes(engagement_id=engagement_id, limit=20_000)
    scannable = {n.id: n for n in nodes if n.asset_type in (AssetType.HOST, AssetType.SUBDOMAIN)}
    if not scannable:
        return []
    edges = graph.list_edges(engagement_id=engagement_id, limit=50_000)
    has_port = {e.source_id for e in edges if e.relationship == "has_port"}
    out = [
        {
            "asset_id": n.id,
            "asset_type": n.asset_type.value,
            "label": n.label,
            "confidence": n.confidence,
            "gap": "no port evidence",
        }
        for nid, n in scannable.items()
        if nid not in has_port
    ]
    return out[:limit]


def unexplained_observations(engagement_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    """Observations not yet tied to any graph asset — the raw material for
    curiosity-driven investigation (Step 4's question/hypothesis scaffold
    reads this to find something to ask about). An observation type this
    module never builds graph structure for (scanner_signal, http_response,
    header, raw, …) is *always* unexplained by definition — that's expected,
    not a gap; it becomes explained once a hypothesis or attack path cites it.
    """
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    graph = get_engagement_graph()
    cited: set[str] = set()
    for n in graph.list_nodes(engagement_id=eid, limit=20_000):
        cited.update(n.observation_ids)
    for e in graph.list_edges(engagement_id=eid, limit=50_000):
        cited.update(e.observation_ids)

    observations = get_observation_store().list_for_engagement(eid, limit=10_000)
    out = [
        {
            "observation_id": o.id,
            "type": o.type.value,
            "target": o.target,
            "source_tool": o.source_tool,
            "details": o.details,
        }
        for o in observations
        if o.id not in cited
    ]
    return out[:limit]


def conflicts(engagement_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
    """Every asset with a disputed slot (Step 2a) — surfaced so the context
    packet (Plan 07) and the LLM/human can resolve it, or a later
    observation breaks the tie."""
    graph = get_engagement_graph()
    nodes = graph.list_nodes(engagement_id=engagement_id, limit=20_000)
    out = [
        {
            "asset_id": n.id,
            "asset_type": n.asset_type.value,
            "label": n.label,
            "conflicts": {
                slot: [c.model_dump() for c in values] for slot, values in n.conflicts.items()
            },
        }
        for n in nodes
        if n.conflicts
    ]
    return out[:limit]
