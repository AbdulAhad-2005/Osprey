"""Queryable engagement graph — filter by type/label without dumping everything."""

from __future__ import annotations

from collections import Counter
from typing import Any

from osprey.schemas.finding import FindingType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.findings_store import get_findings_store

from osprey.services.visualization import _build_severity_map as _build_node_severity_map


def _resolve_node_id(graph, engagement_id: str, from_asset: str) -> str | None:
    """Resolve a human-given asset string ('scanme.nmap.org', 'host:x', ...) to
    an internal node id. Exact type-prefixed ids are used directly; otherwise
    falls back to an exact then substring label search across all node types."""
    from osprey.schemas.engagement_graph import AssetType

    candidate = from_asset.strip()
    if ":" in candidate:
        prefix, _, rest = candidate.partition(":")
        try:
            AssetType(prefix.lower())
            return f"{prefix.lower()}:{rest.lower()}"
        except ValueError:
            pass

    nodes = graph.list_nodes(engagement_id=engagement_id, limit=20_000)
    lowered = candidate.lower()
    for n in nodes:
        if n.label.lower() == lowered:
            return n.id
    for n in nodes:
        if lowered in n.label.lower():
            return n.id
    return None


def _query_multi_hop(
    graph, engagement_id: str, *, from_asset: str, max_hops: int, limit: int
) -> dict[str, Any]:
    start_id = _resolve_node_id(graph, engagement_id, from_asset)
    if not start_id:
        return {
            "engagement_id": engagement_id,
            "from_asset": from_asset,
            "error": f"no node matching {from_asset!r} found in graph",
            "nodes": [],
            "count": 0,
        }

    paths = graph.find_paths_multi_hop(
        engagement_id=engagement_id,
        start_node_id=start_id,
        max_hops=max_hops,
        limit=limit,
    )
    wanted_ids = {p["node_id"] for p in paths}
    node_by_id = {
        n.id: n
        for n in graph.list_nodes(engagement_id=engagement_id, limit=20_000)
        if n.id in wanted_ids
    }
    sev_map = _build_node_severity_map(engagement_id) if paths else {}
    nodes_out = []
    for p in paths:
        nid = p["node_id"]
        node_out: dict[str, Any] = {
            "id": nid,
            "type": getattr(node_by_id[nid].asset_type, "value", "")
            if nid in node_by_id
            else "",
            "label": node_by_id[nid].label if nid in node_by_id else nid,
            "hops": p["hops"],
            "via_relationship": p["via_relationship"],
            "via_from": p["via_from"],
        }
        sev = sev_map.get(nid)
        if sev:
            node_out["max_severity"] = sev
        nodes_out.append(node_out)

    return {
        "engagement_id": engagement_id,
        "from_asset": from_asset,
        "start_node_id": start_id,
        "max_hops": max_hops,
        "count": len(nodes_out),
        "nodes": nodes_out,
        "hint": (
            "Multi-hop traversal from from_asset, sorted by hop distance (closest first) — "
            "an undirected walk of the graph, the same way a human pentester follows "
            "relationships regardless of which way an edge was written. hypothesis_* "
            "relationships are not proof. platform_evidence_chain explains why an edge "
            "exists; platform_graph_link/platform_graph_link_many to add ones you find."
        ),
    }


def query_graph(
    engagement_id: str,
    *,
    asset_type: str = "",
    contains: str = "",
    limit: int = 80,
    from_asset: str = "",
    max_hops: int = 0,
) -> dict[str, Any]:
    if not (engagement_id or "").strip():
        return {"error": "engagement_id required", "nodes": [], "edges": [], "count": 0}

    limit = max(1, min(int(limit), 500))
    contains = (contains or "").strip().lower()
    asset_type = (asset_type or "").strip().lower()
    from_asset = (from_asset or "").strip()

    graph = get_engagement_graph()

    if from_asset and max_hops > 0:
        return _query_multi_hop(
            graph, engagement_id, from_asset=from_asset, max_hops=max_hops, limit=limit
        )

    nodes = graph.list_nodes(
        engagement_id=engagement_id,
        asset_type=asset_type or None,
        limit=20_000,
    )
    sev_map = _build_node_severity_map(engagement_id) if nodes else {}
    matched = []
    for n in nodes:
        label = (n.label or "").strip()
        if contains and contains not in label.lower():
            meta = " ".join(str(v) for v in (n.metadata or {}).values())
            if contains not in meta.lower():
                continue
        node_out: dict[str, Any] = {
            "id": n.id,
            "type": getattr(n.asset_type, "value", str(n.asset_type)),
            "label": label,
            "metadata": n.metadata or {},
        }
        sev = sev_map.get(n.id)
        if sev:
            node_out["max_severity"] = sev
        matched.append(node_out)
        if len(matched) >= limit:
            break

    edges_out: list[dict[str, Any]] = []
    if matched:
        ids = {m["id"] for m in matched}
        for e in graph.list_edges(engagement_id=engagement_id, limit=10_000):
            if e.source_id in ids or e.target_id in ids:
                rel = e.relationship
                edge_out: dict[str, Any] = {
                    "source": e.source_id,
                    "target": e.target_id,
                    "rel": rel,
                    "hypothesis": rel.startswith("hypothesis_"),
                }
                if e.metadata:
                    edge_out["evidence"] = e.metadata
                if e.source_tool:
                    edge_out["source_tool"] = e.source_tool
                edges_out.append(edge_out)
                if len(edges_out) >= limit * 2:
                    break

    return {
        "engagement_id": engagement_id,
        "asset_type": asset_type or "*",
        "contains": contains or "*",
        "count": len(matched),
        "nodes": matched,
        "edges": edges_out[: limit * 2],
        "hint": (
            "Narrow with asset_type=subdomain|host|url|port|ip|technology and contains=vpn|oracle|api. "
            "Operator links: platform_graph_link. hypothesis_*=not proof. "
            "Then platform_fanout_assets or platform_crown_jewels."
        ),
    }
