"""EngagementGraph query/link/summary methods (mixin)."""

from __future__ import annotations
from typing import Any
from sqlalchemy import or_, select
from osprey.db.session import SessionLocal
from osprey.models.finding import AssetEdgeRow, AssetNodeRow
from osprey.schemas.engagement_graph import (
    AssetEdge,
    AssetNode,
    AssetType,
    GraphSummary,
    SiblingHostResponse,
)
from osprey.services.engagement_graph._helpers import (
    logger,
    _node_id,
    _decode_meta,
    _decode_list,
    _decode_conflicts,
)


class _QueryMixin:

    def siblings_same_ip(self, host_or_subdomain: str, *, engagement_id: str = "") -> SiblingHostResponse:
        eid = engagement_id or ""
        with self._lock:
            db = SessionLocal()
            try:
                node_stmt = select(AssetNodeRow)
                edge_stmt = select(AssetEdgeRow)
                if eid:
                    node_stmt = node_stmt.where(AssetNodeRow.engagement_id == eid)
                    edge_stmt = edge_stmt.where(AssetEdgeRow.engagement_id == eid)

                nodes = {(r.engagement_id, r.id): r for r in db.scalars(node_stmt).all()}
                edges = list(db.scalars(edge_stmt).all())
            finally:
                db.close()

        ref = host_or_subdomain.lower().strip()
        ref_id: str | None = None
        for prefix in (AssetType.SUBDOMAIN, AssetType.HOST):
            candidate = _node_id(prefix, ref)
            if eid and (eid, candidate) in nodes:
                ref_id = candidate
                break
            for (row_eid, row_id), _row in nodes.items():
                if row_id == candidate and (not eid or row_eid == eid):
                    ref_id = candidate
                    if not eid:
                        eid = row_eid
                    break
            if ref_id:
                break

        ip_ids: set[str] = set()
        if ref_id:
            for edge in edges:
                if (
                    edge.source_id == ref_id
                    and edge.relationship == "resolves_to"
                    and (not eid or edge.engagement_id == eid)
                ):
                    ip_ids.add(edge.target_id)

        siblings: set[str] = set()
        ips: list[str] = []
        for ip_id in ip_ids:
            ip_node = nodes.get((eid, ip_id))
            if ip_node:
                ips.append(ip_node.label)
            for edge in edges:
                if edge.target_id == ip_id and edge.relationship == "resolves_to":
                    if eid and edge.engagement_id != eid:
                        continue
                    sibling_node = nodes.get((edge.engagement_id, edge.source_id))
                    if sibling_node and sibling_node.label.lower() != ref:
                        siblings.add(sibling_node.label)

        ip_str = ips[0] if ips else ""
        return SiblingHostResponse(
            reference=host_or_subdomain,
            ip=ip_str,
            siblings=sorted(siblings),
            hint=(
                f"{len(siblings)} sibling host(s) on IP {ip_str} — shared hosting signal "
                "(hypothesis until you confirm)"
                if siblings
                else "No IP linkage yet — resolve DNS / probe to populate graph"
            ),
        )

    # ------------------------------------------------------------------
    # Operator-asserted nodes/edges — disclosed exception, see module docstring
    # ------------------------------------------------------------------

    def ensure_node(
        self,
        *,
        engagement_id: str,
        asset_type: AssetType,
        label: str,
        run_id: str = "",
        metadata: dict | None = None,
    ) -> AssetNode:
        """Upsert a node so operator links/tags have an anchor."""
        eid = (engagement_id or "").strip()
        if not eid:
            raise ValueError("engagement_id required")
        lab = (label or "").strip()
        if not lab:
            raise ValueError("label required")
        node = AssetNode(
            id=_node_id(asset_type, lab),
            asset_type=asset_type,
            label=lab,
            engagement_id=eid,
            run_id=run_id or "",
            metadata={str(k): v for k, v in (metadata or {}).items()},
        )
        with self._lock:
            db = SessionLocal()
            try:
                out = self._upsert_node(db, node)
                db.commit()
                return out
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

    def operator_link(
        self,
        *,
        engagement_id: str,
        source_type: AssetType,
        source_label: str,
        target_type: AssetType,
        target_label: str,
        relationship: str,
        run_id: str = "",
        source_tool: str = "",
        metadata: dict | None = None,
    ) -> dict[str, str]:
        """Create an operator-named edge between two assets (nodes upserted)."""
        eid = (engagement_id or "").strip()
        if not eid:
            raise ValueError("engagement_id required")
        rel = (relationship or "").strip()
        if not rel or len(rel) > 64:
            raise ValueError("relationship must be 1–64 chars")
        src_lab = (source_label or "").strip()
        tgt_lab = (target_label or "").strip()
        if not src_lab or not tgt_lab:
            raise ValueError("source and target labels required")

        src = AssetNode(
            id=_node_id(source_type, src_lab), asset_type=source_type, label=src_lab,
            engagement_id=eid, run_id=run_id or "",
        )
        tgt = AssetNode(
            id=_node_id(target_type, tgt_lab), asset_type=target_type, label=tgt_lab,
            engagement_id=eid, run_id=run_id or "",
        )
        with self._lock:
            db = SessionLocal()
            try:
                self._upsert_node(db, src)
                self._upsert_node(db, tgt)
                self._add_edge(
                    db,
                    AssetEdge(
                        source_id=src.id, target_id=tgt.id, relationship=rel, engagement_id=eid,
                        run_id=run_id or "", source_tool=source_tool or "", metadata=metadata or {},
                    ),
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        return {"source_id": src.id, "target_id": tgt.id, "relationship": rel, "engagement_id": eid}

    def operator_link_many(
        self,
        *,
        engagement_id: str,
        edges: list[dict],
        run_id: str = "",
    ) -> list[dict[str, str]]:
        """Create many operator-named edges in one transaction (nodes upserted).

        Each item in ``edges`` is a dict already validated/sanitized by the caller:
        {source_type, source_label, target_type, target_label, relationship}.
        One commit for the whole batch — this is what makes bulk persistence cheap
        enough that an LLM will actually do it instead of skipping it.
        """
        eid = (engagement_id or "").strip()
        if not eid:
            raise ValueError("engagement_id required")
        if not edges:
            return []

        written: list[dict[str, str]] = []
        with self._lock:
            db = SessionLocal()
            try:
                for item in edges:
                    src_type: AssetType = item["source_type"]
                    tgt_type: AssetType = item["target_type"]
                    src_lab = str(item["source_label"]).strip()
                    tgt_lab = str(item["target_label"]).strip()
                    rel = str(item["relationship"]).strip()
                    if not src_lab or not tgt_lab or not rel:
                        continue

                    src = AssetNode(
                        id=_node_id(src_type, src_lab), asset_type=src_type, label=src_lab,
                        engagement_id=eid, run_id=run_id or "",
                    )
                    tgt = AssetNode(
                        id=_node_id(tgt_type, tgt_lab), asset_type=tgt_type, label=tgt_lab,
                        engagement_id=eid, run_id=run_id or "",
                    )
                    self._upsert_node(db, src)
                    self._upsert_node(db, tgt)
                    self._add_edge(
                        db,
                        AssetEdge(
                            source_id=src.id, target_id=tgt.id, relationship=rel, engagement_id=eid,
                            run_id=run_id or "", source_tool=str(item.get("source_tool") or ""),
                            metadata=item.get("metadata") or {},
                        ),
                    )
                    written.append({"source_id": src.id, "target_id": tgt.id, "relationship": rel})
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        return written

    # ------------------------------------------------------------------
    # Read paths
    # ------------------------------------------------------------------

    def list_nodes(
        self,
        *,
        engagement_id: str = "",
        asset_type: AssetType | str | None = None,
        run_id: str = "",
        q: str | None = None,
        node_id: str | None = None,
        limit: int = 5000,
    ) -> list[AssetNode]:
        type_val = asset_type.value if isinstance(asset_type, AssetType) else asset_type
        with self._lock:
            db = SessionLocal()
            try:
                stmt = select(AssetNodeRow)
                if engagement_id:
                    stmt = stmt.where(AssetNodeRow.engagement_id == engagement_id)
                if node_id is not None:
                    stmt = stmt.where(AssetNodeRow.id == node_id)
                if type_val:
                    stmt = stmt.where(AssetNodeRow.asset_type == type_val)
                if run_id:
                    stmt = stmt.where(AssetNodeRow.run_id == run_id)
                if q and q.strip():
                    # Server-side substring match (label / id / type) so recall
                    # never pulls the whole node set into Python to filter it.
                    q_pat = f"%{q.strip()}%"
                    stmt = stmt.where(
                        or_(
                            AssetNodeRow.label.ilike(q_pat),
                            AssetNodeRow.id.ilike(q_pat),
                            AssetNodeRow.asset_type.ilike(q_pat),
                        )
                    )
                stmt = stmt.limit(max(1, min(limit, 20_000)))
                rows = list(db.scalars(stmt).all())
            finally:
                db.close()
        return [
            AssetNode(
                id=r.id,
                asset_type=AssetType(r.asset_type),
                label=r.label,
                engagement_id=r.engagement_id,
                run_id=r.run_id,
                source_tool=getattr(r, "source_tool", "") or "",
                confidence=getattr(r, "confidence", "likely") or "likely",
                observation_ids=_decode_list(getattr(r, "observation_ids_json", "") or "[]"),
                source_tools=_decode_list(getattr(r, "source_tools_json", "") or "[]"),
                conflicts=_decode_conflicts(getattr(r, "conflicts_json", "") or "{}"),
                metadata=_decode_meta(r.metadata_json),
                created_at=getattr(r, "created_at", None),
                updated_at=getattr(r, "updated_at", None),
            )
            for r in rows
        ]

    def list_edges(
        self,
        *,
        engagement_id: str = "",
        relationship: str | None = None,
        limit: int = 10_000,
    ) -> list[AssetEdge]:
        with self._lock:
            db = SessionLocal()
            try:
                stmt = select(AssetEdgeRow)
                if engagement_id:
                    stmt = stmt.where(AssetEdgeRow.engagement_id == engagement_id)
                if relationship:
                    stmt = stmt.where(AssetEdgeRow.relationship == relationship)
                stmt = stmt.limit(max(1, min(limit, 50_000)))
                rows = list(db.scalars(stmt).all())
            finally:
                db.close()
        return [
            AssetEdge(
                source_id=r.source_id,
                target_id=r.target_id,
                relationship=r.relationship,
                engagement_id=r.engagement_id,
                run_id=getattr(r, "run_id", "") or "",
                source_tool=getattr(r, "source_tool", "") or "",
                observation_ids=_decode_list(getattr(r, "observation_ids_json", "") or "[]"),
                metadata=_decode_meta(getattr(r, "metadata_json", "") or ""),
            )
            for r in rows
        ]

    def find_paths_multi_hop(
        self,
        *,
        engagement_id: str,
        start_node_id: str,
        max_hops: int = 3,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Multi-hop neighbor discovery — one indexed SQL query per hop, not a
        full-graph load into Python (the previous limit on every other graph
        traversal in this file). Edges are treated as undirected: "what
        connects to X" shouldn't depend on which way the edge happened to be
        written, matching how a human pentester reasons about relationships.

        Returns nodes reachable from start_node_id within max_hops, each tagged
        with its shortest hop distance and the edge that first reached it —
        sorted by distance so the closest, most relevant connections come first.
        """
        eid = (engagement_id or "").strip()
        start = (start_node_id or "").strip()
        if not eid or not start:
            return []
        hops = max(1, min(int(max_hops), 6))
        cap = max(1, min(int(limit), 1000))

        visited: dict[str, dict[str, Any]] = {}
        frontier: set[str] = {start}
        with self._lock:
            db = SessionLocal()
            try:
                for hop in range(1, hops + 1):
                    if not frontier or len(visited) >= cap:
                        break
                    rows = db.scalars(
                        select(AssetEdgeRow).where(
                            AssetEdgeRow.engagement_id == eid,
                            or_(
                                AssetEdgeRow.source_id.in_(frontier),
                                AssetEdgeRow.target_id.in_(frontier),
                            ),
                        )
                    ).all()
                    next_frontier: set[str] = set()
                    for r in rows:
                        for a, b in ((r.source_id, r.target_id), (r.target_id, r.source_id)):
                            if a in frontier and b != start and b not in visited:
                                visited[b] = {
                                    "node_id": b,
                                    "hops": hop,
                                    "via_relationship": r.relationship,
                                    "via_from": a,
                                }
                                next_frontier.add(b)
                                if len(visited) >= cap:
                                    break
                        if len(visited) >= cap:
                            break
                    frontier = next_frontier
            finally:
                db.close()
        return sorted(visited.values(), key=lambda v: (v["hops"], v["node_id"]))[:cap]

    def summary(
        self,
        *,
        engagement_id: str = "",
        run_id: str = "",
    ) -> GraphSummary:
        if not (engagement_id or "").strip():
            return GraphSummary(
                engagement_id="",
                run_id=run_id,
                node_count=0,
                edge_count=0,
                pivot_hints=["engagement_id required — call platform_health() to bind session"],
            )
        with self._lock:
            db = SessionLocal()
            try:
                node_stmt = select(AssetNodeRow)
                edge_stmt = select(AssetEdgeRow)
                if engagement_id:
                    node_stmt = node_stmt.where(AssetNodeRow.engagement_id == engagement_id)
                    edge_stmt = edge_stmt.where(AssetEdgeRow.engagement_id == engagement_id)
                node_rows = list(db.scalars(node_stmt).all())
                edge_rows = list(db.scalars(edge_stmt).all())
            finally:
                db.close()

        # NOTE: run_id is NOT used to filter the engagement graph summary.
        # MCP sessions mint a new run_id often; filtering made the graph look empty
        # (nodes=0) even when the engagement had hundreds of assets. Graph is
        # engagement-scoped; run_id remains an audit stamp on new writes.

        subdomains = [n.label for n in node_rows if n.asset_type == AssetType.SUBDOMAIN.value]
        live = [
            n.label
            for n in node_rows
            if n.asset_type in (AssetType.URL.value, AssetType.HOST.value)
        ]
        ports = [n.label for n in node_rows if n.asset_type == AssetType.PORT.value]
        techs = [n.label for n in node_rows if n.asset_type == AssetType.TECHNOLOGY.value]

        pivots: list[str] = []
        if len(subdomains) < 5:
            pivots.append("Gap: thin subdomain inventory (few names in graph)")
        if any("445" in p for p in ports):
            pivots.append("Signal: port 445 present — SMB surface may exist (you choose depth)")
        if any("cdn" in (t or "").lower() or "cloudflare" in (t or "").lower() for t in techs):
            pivots.append(
                "Signal: CDN/WAF tech — edge IPs may not be origin (optional origin hunt)"
            )

        # M5: per-IP network granularity instead of dumb "subs but no ports"
        if engagement_id:
            try:
                from osprey.services.network_surface import build_network_surface

                ns = build_network_surface(engagement_id, run_id=run_id)
                if ns is not None:
                    if ns.unscanned_ips:
                        pivots.append(
                            f"Gap: {ns.unscanned_ips} IP(s) without port evidence"
                        )
                    if ns.ports_without_services:
                        pivots.append(
                            f"Gap: {ns.ports_without_services} IP(s) have ports but no SERVICE findings"
                        )
            except Exception:
                logger.debug("network surface pivot failed", exc_info=True)
        elif len(subdomains) >= 2 and not ports:
            pivots.append("Gap: hosts found without port evidence")

        # Soft signals from edges/metadata (engagement already filtered in rows).
        # co_hosts is no longer a persisted edge (Step 1) — siblings_same_ip
        # derives the same signal live from resolves_to, so summary computes
        # its count the same way instead of counting a dropped edge type.
        resolves = [e for e in edge_rows if e.relationship == "resolves_to"]
        ip_to_hosts: dict[str, set[str]] = {}
        for e in resolves:
            ip_to_hosts.setdefault(e.target_id, set()).add(e.source_id)
        co_hosts = sum(len(hosts) for hosts in ip_to_hosts.values() if len(hosts) > 1)
        if co_hosts:
            pivots.append(f"Signal: {co_hosts} host(s) share an IP with another — shared hosting signal")
        affiliated = sum(1 for e in edge_rows if e.relationship == "affiliated_with")
        if affiliated:
            pivots.append(f"Signal: {affiliated} sister/affiliated domain(s) linked from seed")
        cf_nodes = [
            n.label
            for n in node_rows
            if _decode_meta(n.metadata_json).get("is_cloudflare")
        ]
        if cf_nodes:
            sample = ", ".join(cf_nodes[:3])
            pivots.append(f"Signal: Cloudflare/WAF on {sample} — origin hunt is optional")

        return GraphSummary(
            engagement_id=engagement_id,
            run_id=run_id,
            node_count=len(node_rows),
            edge_count=len(edge_rows),
            subdomains=subdomains[:50],
            live_hosts=live[:50],
            open_ports=ports[:50],
            technologies=techs[:30],
            pivot_hints=pivots,
        )
