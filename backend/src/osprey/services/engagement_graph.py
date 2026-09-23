"""Engagement graph — Postgres-backed, strictly scoped per engagement.

Same subdomain/IP labels on different engagements never share nodes or edges.
Composite PK is (engagement_id, node_id) where node_id = asset_type:label.

Since plans/harness/05-world-model-and-attack-paths.md Step 1, ``ingest_observation``
is the primary builder — every node/edge it creates cites the ``observation_id``(s)
that assert it, and confidence is recomputed fresh from the *current* evidence
set on every ingest (never ratcheted from a remembered prior value), so it can
fall as well as rise once Plan 06's decay model or Step 2a's conflict handling
feeds back into it. ``ingest_finding`` still exists, but only to stamp a filed
Finding's link to the graph node(s) its own observation_ids already built —
it mints no new structure itself.

Disclosed exception: ``ensure_node`` / ``operator_link`` / ``operator_link_many``
(behind ``platform_graph_link``/``platform_graph_link_many``) still let an
operator/LLM assert a node or edge with no observation_id — these predate the
evidence law and migrating them is a separately-scoped follow-up (same gap as
``operator_memory.record_think``/``platform_record_finding``). Every
*deterministic* edge this module builds itself always cites evidence.
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Any, Iterable

import orjson
from sqlalchemy import or_, select

from osprey.db.session import SessionLocal
from osprey.models.finding import AssetEdgeRow, AssetNodeRow, FindingRow
from osprey.schemas.engagement_graph import (
    AssetEdge,
    AssetNode,
    AssetType,
    ConflictingValue,
    GraphSummary,
    SiblingHostResponse,
)
from osprey.schemas.finding import Finding
from osprey.schemas.observation import Observation, ObservationType

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _node_id(asset_type: AssetType, label: str) -> str:
    """Local node key within an engagement (engagement_id is a separate PK part)."""
    return f"{asset_type.value}:{label.lower()}"


def _encode_meta(meta: dict) -> str:
    return orjson.dumps(meta).decode()


def _decode_meta(raw: str) -> dict:
    if not raw:
        return {}
    try:
        data = orjson.loads(raw)
        return data if isinstance(data, dict) else {}
    except (orjson.JSONDecodeError, TypeError, ValueError):
        return {}


def _decode_list(raw: str) -> list[str]:
    if not raw:
        return []
    try:
        data = orjson.loads(raw)
        return [str(x) for x in data] if isinstance(data, list) else []
    except (orjson.JSONDecodeError, TypeError, ValueError):
        return []


def _decode_conflicts(raw: str) -> dict[str, list[ConflictingValue]]:
    if not raw:
        return {}
    try:
        data = orjson.loads(raw)
    except (orjson.JSONDecodeError, TypeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, list[ConflictingValue]] = {}
    for slot, entries in data.items():
        if isinstance(entries, list):
            out[str(slot)] = [ConflictingValue.model_validate(e) for e in entries if isinstance(e, dict)]
    return out


def _node_confidence(source_tool_count: int) -> str:
    """The same evidence law as ``services.confidence.confidence_for``, applied
    to a graph node: a fact only one tool ever reported stays a hypothesis;
    two or more independent tools agreeing earns "likely". There is no
    "confirmed" tier for a graph fact — nothing here is a reproduction."""
    return "likely" if source_tool_count >= 2 else "hypothesis"


class EngagementGraph:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Finding link (no structure-building — see module docstring)
    # ------------------------------------------------------------------

    def ingest_finding(self, finding: Finding) -> None:
        self.ingest_many([finding])

    def ingest_many(self, findings: Iterable[Finding]) -> None:
        """Stamp a filed Finding's link to the graph node(s) its own
        observation_ids already built via ``ingest_observation``. Mints no
        new nodes/edges — a Finding is validated evidence *about* the graph,
        not a second way to build it."""
        items = list(findings)
        if not items:
            return
        with self._lock:
            db = SessionLocal()
            try:
                for finding in items:
                    sp = db.begin_nested()
                    try:
                        self._stamp_finding_node_link(db, finding)
                        sp.commit()
                    except Exception as exc:  # noqa: BLE001
                        sp.rollback()
                        logger.debug("graph finding-link skipped: %s", exc)
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

    def _stamp_finding_node_link(self, db, finding: Finding) -> None:
        frow = db.get(FindingRow, finding.id)
        if frow is None or frow.node_id:
            return
        eid = finding.engagement_id or ""
        for oid in finding.observation_ids or []:
            needle = f'"{oid}"'
            row = db.scalars(
                select(AssetNodeRow).where(
                    AssetNodeRow.engagement_id == eid,
                    AssetNodeRow.observation_ids_json.like(f"%{needle}%"),
                )
            ).first()
            if row is not None:
                frow.node_id = row.id
                return

    # ------------------------------------------------------------------
    # Observation ingest — the primary builder (Step 1)
    # ------------------------------------------------------------------

    def ingest_observation(self, obs: Observation) -> None:
        self.ingest_many_observations([obs])

    def ingest_many_observations(self, observations: Iterable[Observation]) -> None:
        items = list(observations)
        if not items:
            return
        with self._lock:
            db = SessionLocal()
            try:
                for obs in items:
                    sp = db.begin_nested()
                    try:
                        self._ingest_observation_one(db, obs)
                        sp.commit()
                    except Exception as exc:  # noqa: BLE001
                        sp.rollback()
                        logger.debug("graph observation ingest skipped one: %s", exc)
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

    def _upsert_node(
        self,
        db,
        node: AssetNode,
        *,
        observation_id: str = "",
        conflict_slot: str = "",
        conflict_value: str = "",
    ) -> AssetNode:
        """Upsert a node, accumulating observation/source-tool provenance and
        recomputing confidence fresh from the current evidence set — never a
        ratchet against a remembered prior value (Step 1).

        ``conflict_slot``/``conflict_value``: when set, this observation's
        claim for that slot is checked against whatever value is already on
        record; a disagreement is recorded in ``conflicts`` (both values kept,
        Step 2a), never silently overwritten.
        """
        eid = node.engagement_id or ""
        existing = db.get(AssetNodeRow, (eid, node.id))
        if existing is None:
            for obj in list(db.new):
                if isinstance(obj, AssetNodeRow) and obj.engagement_id == eid and obj.id == node.id:
                    existing = obj
                    break

        if existing:
            existing_meta = _decode_meta(existing.metadata_json)
            obs_ids = _decode_list(existing.observation_ids_json)
            tools = _decode_list(existing.source_tools_json)
            conflicts = _decode_conflicts(existing.conflicts_json)

            # Conflict check runs against the PRIOR value, before the new
            # observation's metadata is merged in — merging first would
            # silently overwrite the very value being compared against. Once a
            # slot has any recorded conflict, every later observation for it
            # is checked against the whole conflict set (not just whatever
            # metadata currently holds) — the slot never silently "resolves"
            # back to a single value just because a later prior_value lookup
            # came up empty.
            incoming_meta = dict(node.metadata or {})
            if conflict_slot and conflict_value:
                existing_conflicts = conflicts.get(conflict_slot, [])
                prior_value = existing_meta.get(conflict_slot)
                known_values = {c.value.lower() for c in existing_conflicts}
                if prior_value:
                    known_values.add(str(prior_value).lower())
                disputed = bool(existing_conflicts) or (
                    prior_value and str(prior_value).strip().lower() != conflict_value.strip().lower()
                )
                if disputed and conflict_value.strip().lower() not in known_values:
                    slot_conflicts = conflicts.setdefault(conflict_slot, [])
                    if prior_value and not any(c.value.lower() == str(prior_value).lower() for c in slot_conflicts):
                        slot_conflicts.append(ConflictingValue(
                            value=str(prior_value), observation_id="", source_tool=existing.source_tool,
                        ))
                    slot_conflicts.append(ConflictingValue(
                        value=conflict_value, observation_id=observation_id, source_tool=node.source_tool,
                    ))
                if disputed:
                    # Slot is disputed — no single value wins in metadata.
                    existing_meta.pop(conflict_slot, None)
                    incoming_meta.pop(conflict_slot, None)

            merged_meta = {**existing_meta, **incoming_meta}

            if observation_id and observation_id not in obs_ids:
                obs_ids.append(observation_id)
            if node.source_tool and node.source_tool not in tools:
                tools.append(node.source_tool)

            existing.metadata_json = _encode_meta(merged_meta)
            existing.observation_ids_json = _encode_meta(obs_ids)
            existing.source_tools_json = _encode_meta(tools)
            existing.conflicts_json = _encode_meta(
                {k: [c.model_dump() for c in v] for k, v in conflicts.items()}
            )
            existing.run_id = node.run_id or existing.run_id
            existing.label = node.label
            existing.asset_type = node.asset_type.value
            if node.source_tool and not existing.source_tool:
                existing.source_tool = node.source_tool
            existing.confidence = _node_confidence(len(tools))
            return AssetNode(
                id=existing.id, asset_type=AssetType(existing.asset_type), label=existing.label,
                engagement_id=existing.engagement_id, run_id=existing.run_id,
                source_tool=existing.source_tool, confidence=existing.confidence,
                observation_ids=obs_ids, source_tools=tools, conflicts=conflicts,
                metadata=merged_meta,
            )

        obs_ids = [observation_id] if observation_id else []
        tools = [node.source_tool] if node.source_tool else []
        row = AssetNodeRow(
            engagement_id=eid,
            id=node.id,
            asset_type=node.asset_type.value,
            label=node.label,
            run_id=node.run_id or "",
            source_tool=node.source_tool or "",
            confidence=_node_confidence(len(tools)),
            observation_ids_json=_encode_meta(obs_ids),
            source_tools_json=_encode_meta(tools),
            conflicts_json="{}",
            metadata_json=_encode_meta(node.metadata or {}),
        )
        db.add(row)
        return node.model_copy(update={"observation_ids": obs_ids, "source_tools": tools})

    def _add_edge(self, db, edge: AssetEdge, *, observation_id: str = "") -> None:
        if edge.source_id == edge.target_id:
            return
        eid = edge.engagement_id or ""
        existing = db.scalars(
            select(AssetEdgeRow).where(
                AssetEdgeRow.engagement_id == eid,
                AssetEdgeRow.source_id == edge.source_id,
                AssetEdgeRow.target_id == edge.target_id,
                AssetEdgeRow.relationship == edge.relationship,
            )
        ).first()
        if existing:
            if observation_id:
                obs_ids = _decode_list(existing.observation_ids_json)
                if observation_id not in obs_ids:
                    obs_ids.append(observation_id)
                    existing.observation_ids_json = _encode_meta(obs_ids)
            return
        db.add(
            AssetEdgeRow(
                engagement_id=eid,
                source_id=edge.source_id,
                target_id=edge.target_id,
                relationship=edge.relationship,
                run_id=edge.run_id or "",
                source_tool=edge.source_tool or "",
                observation_ids_json=_encode_meta([observation_id] if observation_id else []),
                metadata_json=_encode_meta(edge.metadata or {}),
            )
        )

    def _link_resolves(self, db, *, host_node_id: str, ip: str, eid: str, rid: str, observation_id: str) -> None:
        """resolves_to edge only — the old co_hosts heuristic (two hosts
        sharing an IP might be related infra) minted an edge with no
        observation backing it (Step 1 explicitly calls this out: "linked
        unrelated hosts on a shared CDN IP"). That information is still fully
        queryable live from resolves_to edges (see ``siblings_same_ip``,
        which already derives it this way and never used co_hosts) — it just
        isn't persisted as its own unbacked edge type anymore."""
        if not ip:
            return
        ip_node = self._upsert_node(
            db,
            AssetNode(id=_node_id(AssetType.IP, ip), asset_type=AssetType.IP, label=ip,
                      engagement_id=eid, run_id=rid, source_tool=""),
            observation_id=observation_id,
        )
        self._add_edge(
            db,
            AssetEdge(source_id=host_node_id, target_id=ip_node.id, relationship="resolves_to",
                      engagement_id=eid, run_id=rid),
            observation_id=observation_id,
        )

    def _is_sister_observation(self, obs: Observation) -> bool:
        if "sister_domain" in (obs.tags or []):
            return True
        if obs.source_tool == "domain_hunter":
            return True
        role = str(obs.details.get("role", "")).lower()
        return role in ("sister_domain", "sister", "affiliated")

    def _osint_node(
        self, db, *, atype: AssetType, label: str, eid: str, rid: str,
        meta: dict | None = None, source_tool: str = "", observation_id: str = "",
    ) -> AssetNode:
        return self._upsert_node(
            db,
            AssetNode(id=_node_id(atype, label), asset_type=atype, label=label,
                      engagement_id=eid, run_id=rid, source_tool=source_tool, metadata=meta or {}),
            observation_id=observation_id,
        )

    def _resolve_or_seed_domain(self, db, *, seed: str, eid: str, rid: str, observation_id: str) -> AssetNode:
        """Attach lineage edges to an existing node for `seed` rather than
        always minting a fresh DOMAIN placeholder — see the original
        docstring reasoning (a recursively-discovered subdomain seed must not
        duplicate as a second, never-expanded DOMAIN node)."""
        existing = db.get(AssetNodeRow, (eid, _node_id(AssetType.SUBDOMAIN, seed)))
        if existing is not None:
            return AssetNode(
                id=existing.id, asset_type=AssetType.SUBDOMAIN, label=existing.label,
                engagement_id=existing.engagement_id, run_id=existing.run_id,
                source_tool=existing.source_tool, confidence=existing.confidence,
                observation_ids=_decode_list(existing.observation_ids_json),
                source_tools=_decode_list(existing.source_tools_json),
                metadata=_decode_meta(existing.metadata_json),
            )
        return self._upsert_node(
            db,
            AssetNode(id=_node_id(AssetType.DOMAIN, seed), asset_type=AssetType.DOMAIN, label=seed,
                      engagement_id=eid, run_id=rid, metadata={"role": "seed"}),
            observation_id=observation_id,
        )

    def _osint_edge(self, db, *, src: str, tgt: str, rel: str, eid: str, observation_id: str) -> None:
        self._add_edge(
            db, AssetEdge(source_id=src, target_id=tgt, relationship=rel, engagement_id=eid),
            observation_id=observation_id,
        )

    def _ingest_observation_one(self, db, obs: Observation) -> None:
        eid = obs.engagement_id or ""
        rid = obs.run_id or ""
        d = obs.details or {}
        oid = obs.id
        tool = obs.source_tool

        if obs.type == ObservationType.SUBDOMAIN:
            label = str(d.get("hostname") or obs.target).strip().lower()
            if not label:
                return
            node = self._upsert_node(
                db,
                AssetNode(id=_node_id(AssetType.SUBDOMAIN, label), asset_type=AssetType.SUBDOMAIN,
                          label=label, engagement_id=eid, run_id=rid, source_tool=tool, metadata=dict(d)),
                observation_id=oid,
            )
            ip = str(d.get("ip", "") or "")
            if not ip:
                ip_match = _IP_RE.search(str(d))
                ip = ip_match.group(0) if ip_match else ""
            self._link_resolves(db, host_node_id=node.id, ip=ip, eid=eid, rid=rid, observation_id=oid)

            # Auto-skeleton: subdomain -> subdomain_of -> parent domain. Parsers
            # pass the enumerated root as `target`; this is deterministic
            # structure, not LLM cognition, so the platform builds it unasked.
            seed = (obs.target or "").strip().lower()
            if seed and seed != label and label.endswith("." + seed):
                domain_node = self._resolve_or_seed_domain(db, seed=seed, eid=eid, rid=rid, observation_id=oid)
                self._add_edge(
                    db, AssetEdge(source_id=node.id, target_id=domain_node.id,
                                  relationship="subdomain_of", engagement_id=eid),
                    observation_id=oid,
                )

        elif obs.type == ObservationType.URL:
            label = str(d.get("url") or obs.target).strip()
            if not label:
                return
            self._upsert_node(
                db,
                AssetNode(id=_node_id(AssetType.URL, label), asset_type=AssetType.URL, label=label,
                          engagement_id=eid, run_id=rid, source_tool=tool, metadata=dict(d)),
                observation_id=oid,
            )
            host = label.split("//")[-1].split("/")[0].split(":")[0]
            if host:
                host_meta = {"hostname": host}
                if d.get("is_cloudflare"):
                    host_meta["is_cloudflare"] = True
                    host_meta["waf"] = str(d.get("waf") or "cloudflare")
                host_node = self._upsert_node(
                    db,
                    AssetNode(id=_node_id(AssetType.HOST, host), asset_type=AssetType.HOST, label=host,
                              engagement_id=eid, run_id=rid, source_tool=tool, metadata=host_meta),
                    observation_id=oid,
                )
                self._add_edge(
                    db, AssetEdge(source_id=_node_id(AssetType.URL, label), target_id=host_node.id,
                                  relationship="hosted_on", engagement_id=eid),
                    observation_id=oid,
                )

        elif obs.type == ObservationType.PORT:
            host = str(d.get("hostname") or d.get("ip") or obs.target).strip()
            port = str(d.get("port", "") or "")
            port_label = f"{host}:{port}" if port else host
            if not port_label:
                return
            self._upsert_node(
                db,
                AssetNode(id=_node_id(AssetType.PORT, port_label), asset_type=AssetType.PORT,
                          label=port_label, engagement_id=eid, run_id=rid, source_tool=tool, metadata=dict(d)),
                observation_id=oid,
            )
            if host:
                self._upsert_node(
                    db,
                    AssetNode(id=_node_id(AssetType.HOST, host), asset_type=AssetType.HOST, label=host,
                              engagement_id=eid, run_id=rid, source_tool=tool),
                    observation_id=oid,
                )
                self._add_edge(
                    db, AssetEdge(source_id=_node_id(AssetType.HOST, host),
                                  target_id=_node_id(AssetType.PORT, port_label),
                                  relationship="has_port", engagement_id=eid),
                    observation_id=oid,
                )

        elif obs.type == ObservationType.SERVICE:
            host = str(d.get("hostname") or d.get("ip") or obs.target).strip()
            port = str(d.get("port", "") or "")
            service_name = str(d.get("service") or "").strip()
            label = f"{host}:{port} {service_name}".strip() if port else (service_name or obs.target)
            if not label:
                return
            service_node = self._upsert_node(
                db,
                AssetNode(id=_node_id(AssetType.SERVICE, label), asset_type=AssetType.SERVICE, label=label,
                          engagement_id=eid, run_id=rid, source_tool=tool, metadata=dict(d)),
                observation_id=oid,
            )
            if host and port:
                port_label = f"{host}:{port}"
                self._upsert_node(
                    db,
                    AssetNode(id=_node_id(AssetType.HOST, host), asset_type=AssetType.HOST, label=host,
                              engagement_id=eid, run_id=rid, source_tool=tool),
                    observation_id=oid,
                )
                # Step 2a: two tools reporting a different `service` name for
                # the SAME host:port is a real conflict — keep both, mark
                # disputed, never silently overwrite.
                port_node = self._upsert_node(
                    db,
                    AssetNode(id=_node_id(AssetType.PORT, port_label), asset_type=AssetType.PORT,
                              label=port_label, engagement_id=eid, run_id=rid, source_tool=tool,
                              metadata={"service": service_name} if service_name else {}),
                    observation_id=oid,
                    conflict_slot="service" if service_name else "",
                    conflict_value=service_name,
                )
                self._add_edge(
                    db, AssetEdge(source_id=_node_id(AssetType.HOST, host), target_id=port_node.id,
                                  relationship="has_port", engagement_id=eid),
                    observation_id=oid,
                )
                self._add_edge(
                    db, AssetEdge(source_id=port_node.id, target_id=service_node.id,
                                  relationship="runs_service", engagement_id=eid),
                    observation_id=oid,
                )

        elif obs.type == ObservationType.TECHNOLOGY:
            tech = str(d.get("name") or obs.target).strip()
            if not tech:
                return
            tech_node = self._upsert_node(
                db,
                AssetNode(id=_node_id(AssetType.TECHNOLOGY, tech), asset_type=AssetType.TECHNOLOGY,
                          label=tech, engagement_id=eid, run_id=rid, source_tool=tool, metadata=dict(d)),
                observation_id=oid,
            )
            host = str(d.get("hostname", "") or "")
            if not host:
                candidate = (obs.target or "").strip()
                if candidate.lower().startswith(("http://", "https://")):
                    host = candidate.split("//", 1)[-1].split("/")[0].split(":")[0]
                elif candidate and " " not in candidate and "." in candidate:
                    host = candidate
            if host:
                host_node = self._upsert_node(
                    db,
                    AssetNode(id=_node_id(AssetType.HOST, host), asset_type=AssetType.HOST, label=host,
                              engagement_id=eid, run_id=rid, source_tool=tool),
                    observation_id=oid,
                )
                self._add_edge(
                    db, AssetEdge(source_id=host_node.id, target_id=tech_node.id,
                                  relationship="runs_tech", engagement_id=eid),
                    observation_id=oid,
                )

        elif obs.type == ObservationType.HOST:
            label = str(d.get("hostname") or d.get("ip") or obs.target).strip().lower()
            if not label:
                return
            meta = dict(d)
            if self._is_sister_observation(obs):
                meta.setdefault("role", "sister_domain")
            host_node = self._upsert_node(
                db,
                AssetNode(id=_node_id(AssetType.HOST, label), asset_type=AssetType.HOST, label=label,
                          engagement_id=eid, run_id=rid, source_tool=tool, metadata=meta),
                observation_id=oid,
            )
            seed = (obs.target or "").strip().lower()
            if seed and self._is_sister_observation(obs) and seed != label:
                seed_node = self._resolve_or_seed_domain(db, seed=seed, eid=eid, rid=rid, observation_id=oid)
                self._add_edge(
                    db, AssetEdge(source_id=seed_node.id, target_id=host_node.id,
                                  relationship="affiliated_with", engagement_id=eid),
                    observation_id=oid,
                )
            ip = str(meta.get("ip", "") or "")
            if not ip:
                ip_match = _IP_RE.search(str(d))
                ip = ip_match.group(0) if ip_match else ""
            self._link_resolves(db, host_node_id=host_node.id, ip=ip, eid=eid, rid=rid, observation_id=oid)

            # CDN-origin lineage: fronted host -> origin_of -> discovered origin
            # IP. cdn_origin_probe tags its candidates role=="origin_candidate"
            # with obs.target set to the CDN-fronted host it probed.
            if meta.get("role") == "origin_candidate" and seed and seed != label:
                fronted_node = self._upsert_node(
                    db,
                    AssetNode(id=_node_id(AssetType.HOST, seed), asset_type=AssetType.HOST, label=seed,
                              engagement_id=eid, run_id=rid, source_tool=tool, metadata={"behind_cdn": True}),
                    observation_id=oid,
                )
                self._add_edge(
                    db, AssetEdge(source_id=fronted_node.id, target_id=host_node.id,
                                  relationship="origin_of", engagement_id=eid,
                                  metadata={"probe_confidence": meta.get("probe_confidence"),
                                            "signals": meta.get("signals", "")}),
                    observation_id=oid,
                )

        # -- Passive OSINT identity entities --------------------------------
        elif obs.type == ObservationType.EMAIL:
            addr = str(d.get("email") or obs.target).strip().lower()
            if not addr:
                return
            email_node = self._osint_node(db, atype=AssetType.EMAIL, label=addr, eid=eid, rid=rid,
                                           meta=dict(d), source_tool=tool, observation_id=oid)
            if "@" in addr:
                dom = addr.split("@")[-1].strip()
                if dom and "." in dom:
                    dom_node = self._osint_node(db, atype=AssetType.DOMAIN, label=dom, eid=eid, rid=rid,
                                                 meta={"role": "email_domain"}, observation_id=oid)
                    self._osint_edge(db, src=dom_node.id, tgt=email_node.id, rel="has_email", eid=eid, observation_id=oid)
            person = str(d.get("person", "") or "").strip()
            if person:
                p_node = self._osint_node(db, atype=AssetType.PERSON, label=person, eid=eid, rid=rid, observation_id=oid)
                self._osint_edge(db, src=p_node.id, tgt=email_node.id, rel="owns_email", eid=eid, observation_id=oid)

        elif obs.type == ObservationType.USERNAME:
            label = str(obs.target or d.get("username", "")).strip()
            if not label:
                return
            u_node = self._osint_node(db, atype=AssetType.USERNAME, label=label, eid=eid, rid=rid,
                                       meta=dict(d), source_tool=tool, observation_id=oid)
            person = str(d.get("person", "") or "").strip()
            if person:
                p_node = self._osint_node(db, atype=AssetType.PERSON, label=person, eid=eid, rid=rid, observation_id=oid)
                self._osint_edge(db, src=p_node.id, tgt=u_node.id, rel="uses_username", eid=eid, observation_id=oid)

        elif obs.type == ObservationType.PERSON:
            label = str(obs.target or d.get("person", "")).strip()
            if not label:
                return
            p_node = self._osint_node(db, atype=AssetType.PERSON, label=label, eid=eid, rid=rid,
                                       meta=dict(d), source_tool=tool, observation_id=oid)
            org = str(d.get("organization", "") or "").strip()
            if org:
                org_node = self._osint_node(db, atype=AssetType.ORGANIZATION, label=org, eid=eid, rid=rid, observation_id=oid)
                self._osint_edge(db, src=p_node.id, tgt=org_node.id, rel="works_at", eid=eid, observation_id=oid)

        elif obs.type == ObservationType.PHONE:
            label = str(obs.target or d.get("phone", "")).strip()
            if not label:
                return
            ph_node = self._osint_node(db, atype=AssetType.PHONE, label=label, eid=eid, rid=rid,
                                        meta=dict(d), source_tool=tool, observation_id=oid)
            person = str(d.get("person", "") or "").strip()
            if person:
                p_node = self._osint_node(db, atype=AssetType.PERSON, label=person, eid=eid, rid=rid, observation_id=oid)
                self._osint_edge(db, src=p_node.id, tgt=ph_node.id, rel="has_phone", eid=eid, observation_id=oid)

        elif obs.type == ObservationType.SOCIAL_ACCOUNT:
            label = str(d.get("url") or obs.target).strip()
            if not label:
                return
            sa_node = self._osint_node(db, atype=AssetType.SOCIAL_ACCOUNT, label=label, eid=eid, rid=rid,
                                        meta=dict(d), source_tool=tool, observation_id=oid)
            uname = str(d.get("username", "") or "").strip()
            if uname:
                u_node = self._osint_node(db, atype=AssetType.USERNAME, label=uname, eid=eid, rid=rid, observation_id=oid)
                self._osint_edge(db, src=u_node.id, tgt=sa_node.id, rel="used_on", eid=eid, observation_id=oid)
            person = str(d.get("person", "") or "").strip()
            if person:
                p_node = self._osint_node(db, atype=AssetType.PERSON, label=person, eid=eid, rid=rid, observation_id=oid)
                self._osint_edge(db, src=sa_node.id, tgt=p_node.id, rel="belongs_to", eid=eid, observation_id=oid)

        elif obs.type == ObservationType.ORGANIZATION:
            label = str(obs.target or d.get("organization", "")).strip()
            if not label:
                return
            org_node = self._osint_node(db, atype=AssetType.ORGANIZATION, label=label, eid=eid, rid=rid,
                                         meta=dict(d), source_tool=tool, observation_id=oid)
            dom = str(d.get("domain", "") or "").strip().lower()
            if dom and "." in dom:
                dom_node = self._osint_node(db, atype=AssetType.DOMAIN, label=dom, eid=eid, rid=rid, observation_id=oid)
                self._osint_edge(db, src=org_node.id, tgt=dom_node.id, rel="owns_domain", eid=eid, observation_id=oid)

        elif obs.type == ObservationType.DOCUMENT:
            label = str(obs.target or d.get("url", "")).strip()
            if not label:
                return
            doc_node = self._osint_node(db, atype=AssetType.DOCUMENT, label=label, eid=eid, rid=rid,
                                         meta=dict(d), source_tool=tool, observation_id=oid)
            dom = str(d.get("domain", "") or "").strip().lower()
            if dom and "." in dom:
                dom_node = self._osint_node(db, atype=AssetType.DOMAIN, label=dom, eid=eid, rid=rid, observation_id=oid)
                self._osint_edge(db, src=dom_node.id, tgt=doc_node.id, rel="exposes_document", eid=eid, observation_id=oid)
            author = str(d.get("person", "") or d.get("author", "") or "").strip()
            if author:
                p_node = self._osint_node(db, atype=AssetType.PERSON, label=author, eid=eid, rid=rid, observation_id=oid)
                self._osint_edge(db, src=doc_node.id, tgt=p_node.id, rel="authored_by", eid=eid, observation_id=oid)

        elif obs.type == ObservationType.DNS_RECORD:
            # MX/NS/CNAME carry a hostname value -> a real HOST node, linked
            # to the record's owner. TXT/SPF/DNSSEC/registration facts are
            # strings, not assets — they stay on the observation, no node.
            rtype = str(d.get("record_type", "") or "").lower()
            owner = str(d.get("hostname", "") or "").strip().lower().rstrip(".")
            value = str(d.get(rtype) or d.get("value") or d.get("ns") or "").strip().lower().rstrip(".")
            rel = {"mx": "has_mx_record", "ns": "has_ns_record", "cname": "cname_to"}.get(rtype)
            if owner and value and rel:
                owner_node = self._osint_node(
                    db, atype=self._existing_or_guess_host_type(db, owner, eid), label=owner, eid=eid, rid=rid,
                    meta={"role": "dns_owner"}, source_tool=tool, observation_id=oid,
                )
                val_node = self._osint_node(
                    db, atype=AssetType.HOST, label=value, eid=eid, rid=rid,
                    meta={"role": f"{rtype}_target"}, observation_id=oid,
                )
                self._osint_edge(db, src=owner_node.id, tgt=val_node.id, rel=rel, eid=eid, observation_id=oid)

        elif obs.type in (ObservationType.CREDENTIAL, ObservationType.SECRET):
            # A credential/secret is only useful if you know where it belongs
            # — link it to the host/domain it was found on.
            atype = AssetType.CREDENTIAL if obs.type == ObservationType.CREDENTIAL else AssetType.SECRET
            label = str(
                d.get("username") or d.get("email") or d.get("secret_type") or obs.target
            ).strip()
            if not label:
                return
            cred_node = self._osint_node(db, atype=atype, label=label, eid=eid, rid=rid,
                                          meta=dict(d), source_tool=tool, observation_id=oid)
            host = str(d.get("hostname") or d.get("host") or d.get("ip") or obs.target or "").strip().lower()
            if "://" in host or "/" in host:
                from urllib.parse import urlparse

                parsed = urlparse(host if "://" in host else f"//{host}")
                host = (parsed.netloc or parsed.path.split("/")[0]).split("@")[-1].split(":")[0]
            host = host.rstrip(".")
            if host and "." in host:
                host_node = self._osint_node(
                    db, atype=self._existing_or_guess_host_type(db, host, eid), label=host, eid=eid, rid=rid,
                    observation_id=oid,
                )
                rel = "exposes_credential" if atype == AssetType.CREDENTIAL else "exposes_secret"
                self._osint_edge(db, src=host_node.id, tgt=cred_node.id, rel=rel, eid=eid, observation_id=oid)

        # Every other observation type (scanner_signal, injection_point,
        # http_response, header, cookie, redirect, cert, waf, share, account,
        # asn, raw, …) stays a pure observation-store fact — no graph node.
        # This matches the old Finding pipeline exactly: FindingType.OBSERVATION
        # never built graph structure either.

    def _existing_or_guess_host_type(self, db, label: str, eid: str) -> AssetType:
        """Pick the node type for a hostname: reuse an existing domain/subdomain
        node if one is already in the graph, else infer apex (<=2 labels) vs
        subdomain from depth. Avoids creating a duplicate DOMAIN node for a name
        already tracked as a SUBDOMAIN (and vice versa)."""
        for atype in (AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.HOST):
            if db.get(AssetNodeRow, (eid, _node_id(atype, label))):
                return atype
        return AssetType.DOMAIN if label.count(".") <= 1 else AssetType.SUBDOMAIN

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
        limit: int = 5000,
    ) -> list[AssetNode]:
        type_val = asset_type.value if isinstance(asset_type, AssetType) else asset_type
        with self._lock:
            db = SessionLocal()
            try:
                stmt = select(AssetNodeRow)
                if engagement_id:
                    stmt = stmt.where(AssetNodeRow.engagement_id == engagement_id)
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


_graph: EngagementGraph | None = None


def get_engagement_graph() -> EngagementGraph:
    global _graph
    if _graph is None:
        _graph = EngagementGraph()
    return _graph
