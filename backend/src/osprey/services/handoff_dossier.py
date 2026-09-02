"""Self-contained engagement dossier for a zero-context downstream agent.

The exploitation / post-exploitation agent gets NO prior LLM/agent context — only
what recon/enum/scanning persisted. This assembles everything it needs from the
durable store + graph in one payload: complete findings, an asset inventory with
attributes, credentials/secrets, vulnerabilities, entry points, and the relationship
graph — each carrying provenance and evidence grade so the next agent can trust and
verify without re-deriving.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.finding import Finding, FindingType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.engagement_store import get_engagement_store
from osprey.services.findings_store import get_findings_store

_HOST_TYPES = (AssetType.HOST, AssetType.SUBDOMAIN)
_CREDENTIAL_TYPES = (FindingType.CREDENTIAL, FindingType.SECRET)
_ENTRY_POINT_TYPES = (FindingType.URL, FindingType.HTTP_RESPONSE)


def _finding_dict(f: Finding) -> dict[str, Any]:
    """The complete finding record — nothing a downstream agent would need is dropped."""
    return {
        "id": f.id,
        "finding_type": f.finding_type.value,
        "title": f.title,
        "description": f.description,
        "evidence": f.evidence,
        "evidence_grade": f.evidence_grade.value,
        "claim_severity": f.claim_severity.value,
        "confidence": f.confidence.value,
        "source_tool": f.source_tool,
        "target": f.target,
        "phase": f.phase,
        "tags": list(f.tags or []),
        "metadata": dict(f.metadata or {}),
        "occurrence_count": f.occurrence_count if f.occurrence_count is not None else 1,
        "node_id": f.node_id,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def _node_dict(node) -> dict[str, Any]:
    return {
        "id": node.id,
        "asset_type": node.asset_type.value,
        "label": node.label,
        "source_tool": node.source_tool,
        "evidence_grade": node.evidence_grade,
        "confidence": node.confidence,
        "metadata": dict(node.metadata or {}),
    }


def _edge_dict(edge) -> dict[str, Any]:
    return {
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "relationship": edge.relationship,
        "source_tool": edge.source_tool,
        "metadata": dict(edge.metadata or {}),
    }


def _build_assets(nodes, node_by_id, out_edges) -> list[dict[str, Any]]:
    """Per-host inventory: ip, ports+services, technologies, waf/cdn/os — from the graph.

    The same hostname can appear as both a HOST and a SUBDOMAIN node (ports may hang
    off one, the resolved IP off the other), so assets are merged by hostname into a
    single coherent record instead of fragmenting across node types.
    """
    assets: dict[str, dict[str, Any]] = {}
    for node in nodes:
        if node.asset_type not in _HOST_TYPES:
            continue
        key = (node.label or "").strip().lower()
        if not key:
            continue
        asset = assets.setdefault(
            key,
            {
                "label": node.label,
                "asset_type": node.asset_type.value,
                "ip": "",
                "resolved_ips": [],
                "ports": [],
                "technologies": [],
                "waf": "",
                "is_cloudflare": False,
                "os": "",
                "source_tool": "",
                "evidence_grade": "inferred",
                "metadata": {},
            },
        )
        meta = node.metadata or {}
        asset["metadata"] = {**asset["metadata"], **meta}
        asset["ip"] = asset["ip"] or str(meta.get("ip") or "")
        asset["waf"] = asset["waf"] or (meta.get("waf") or "")
        asset["is_cloudflare"] = asset["is_cloudflare"] or bool(meta.get("is_cloudflare"))
        asset["os"] = asset["os"] or (meta.get("os") or "")
        asset["source_tool"] = asset["source_tool"] or node.source_tool

        # Traverse this node's edges, plus its resolved IP node's edges (ports may
        # be attached to either depending on the discovering tool).
        frontier = [node.id]
        for edge in out_edges.get(node.id, []):
            tgt = node_by_id.get(edge.target_id)
            if edge.relationship == "resolves_to" and tgt and tgt.asset_type == AssetType.IP:
                if tgt.label not in asset["resolved_ips"]:
                    asset["resolved_ips"].append(tgt.label)
                asset["ip"] = asset["ip"] or tgt.label
                frontier.append(tgt.id)
        for src_id in frontier:
            for edge in out_edges.get(src_id, []):
                tgt = node_by_id.get(edge.target_id)
                if tgt is None:
                    continue
                if edge.relationship == "has_port":
                    pmeta = tgt.metadata or {}
                    entry = {
                        "port": pmeta.get("port") or tgt.label,
                        "protocol": pmeta.get("protocol") or pmeta.get("proto") or "",
                        "service": pmeta.get("service") or "",
                        "version": pmeta.get("version") or "",
                    }
                    for sub in out_edges.get(tgt.id, []):
                        if sub.relationship == "runs_service":
                            svc = node_by_id.get(sub.target_id)
                            if svc:
                                entry["service"] = entry["service"] or svc.label
                    if entry not in asset["ports"]:
                        asset["ports"].append(entry)
                elif edge.relationship == "runs_tech":
                    if tgt.label not in asset["technologies"]:
                        asset["technologies"].append(tgt.label)
    return list(assets.values())


def build_handoff_dossier(engagement_id: str, *, run_id: str = "") -> dict[str, Any]:
    if not (engagement_id or "").strip():
        return {"engagement_id": "", "error": "engagement_id required", "findings": []}

    store = get_findings_store()
    graph = get_engagement_graph()
    eng = get_engagement_store().get(engagement_id)

    findings = store.list(engagement_id=engagement_id, run_id=run_id or None, limit=10_000)
    nodes = graph.list_nodes(engagement_id=engagement_id, limit=20_000)
    edges = graph.list_edges(engagement_id=engagement_id, limit=20_000)

    node_by_id = {n.id: n for n in nodes}
    out_edges: dict[str, list] = defaultdict(list)
    for edge in edges:
        out_edges[edge.source_id].append(edge)

    by_type: Counter = Counter()
    by_severity: Counter = Counter()
    by_grade: Counter = Counter()
    for f in findings:
        by_type[f.finding_type.value] += 1
        by_severity[f.claim_severity.value] += 1
        by_grade[f.evidence_grade.value] += 1

    return {
        "engagement_id": engagement_id,
        "target": eng.target if eng else "",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "findings": len(findings),
            "nodes": len(nodes),
            "edges": len(edges),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "by_grade": dict(by_grade),
        },
        "assets": _build_assets(nodes, node_by_id, out_edges),
        "credentials": [_finding_dict(f) for f in findings if f.finding_type in _CREDENTIAL_TYPES],
        "vulnerabilities": [
            _finding_dict(f) for f in findings if f.finding_type == FindingType.VULNERABILITY
        ],
        "entry_points": [_finding_dict(f) for f in findings if f.finding_type in _ENTRY_POINT_TYPES],
        "findings": [_finding_dict(f) for f in findings],
        "graph": {
            "nodes": [_node_dict(n) for n in nodes],
            "edges": [_edge_dict(e) for e in edges],
        },
    }
