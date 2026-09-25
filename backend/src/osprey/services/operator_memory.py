"""Operator write-back into engagement memory (graph links, durable hypotheses).

The LLM authors relations and hypotheses here. Neither ``link_assets``/
``link_assets_many`` nor ``record_think`` mint a ``Finding`` — a graph edge's
confidence lives in its own metadata, and operator thinking is a Hypothesis
(services/hypothesis_store.py, Plan 05), never a Finding with a caller-
asserted confidence (Plan 03's one law: confidence is computed from
evidence, never set by a caller).
"""

from __future__ import annotations

import re
from typing import Any

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.finding import FindingConfidence
from osprey.services.engagement_graph import get_engagement_graph

_REL_SAFE = re.compile(r"^[a-z][a-z0-9_]{0,48}$")
_HYPOTHESIS_PREFIX = "hypothesis_"
_MAX_REL_LEN = 64  # matches AssetEdgeRow.relationship column


def sanitize_relation(relation: str, *, confidence: str = "likely") -> str:
    """Normalize operator relation names; anything short of confirmed → hypothesis_ prefix."""
    raw = (relation or "").strip().lower().replace("-", "_").replace(" ", "_")
    raw = re.sub(r"[^a-z0-9_]", "", raw)
    raw = re.sub(r"_+", "_", raw).strip("_")
    if not raw:
        raise ValueError("relation must contain letters (e.g. same_app_as)")
    if not _REL_SAFE.match(raw) and not raw.startswith(_HYPOTHESIS_PREFIX):
        # still allow longer cleaned names truncated below
        if not re.match(r"^[a-z0-9_]+$", raw):
            raise ValueError(f"invalid relation {relation!r}")

    conf = (confidence or "likely").strip().lower()
    if conf not in ("confirmed", "likely", "hypothesis"):
        conf = "likely"

    if conf == "confirmed":
        # Never let operator mint a bare reserved structural edge as "proof" of
        # something else — they may still use custom names freely.
        name = raw[:_MAX_REL_LEN]
    else:
        base = raw
        if base.startswith(_HYPOTHESIS_PREFIX):
            base = base[len(_HYPOTHESIS_PREFIX) :]
        name = f"{_HYPOTHESIS_PREFIX}{base}"[:_MAX_REL_LEN]

    if not name:
        raise ValueError("relation empty after sanitize")
    return name


def is_hypothesis_relation(relationship: str) -> bool:
    return (relationship or "").startswith(_HYPOTHESIS_PREFIX)


def parse_asset_ref(ref: str) -> tuple[AssetType, str]:
    """Parse 'host:erp.x.com' or bare 'erp.x.com' / IP / URL into (type, label)."""
    text = (ref or "").strip()
    if not text:
        raise ValueError("asset ref is empty")

    known = {t.value for t in AssetType}
    if ":" in text:
        prefix, rest = text.split(":", 1)
        p = prefix.strip().lower()
        if p in known and rest.strip():
            # url:https://... keeps the rest intact
            label = rest.strip()
            if p == "url" and not label.startswith("http"):
                # allow url:/path by keeping as-is; prefer full URLs
                pass
            return AssetType(p), label

    lower = text.lower()
    if lower.startswith("http://") or lower.startswith("https://"):
        return AssetType.URL, text
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", text):
        return AssetType.IP, text
    if text.startswith("/") and " " not in text:
        return AssetType.URL, text
    # hostname / subdomain
    if "." in text:
        return AssetType.HOST, text.lower()
    return AssetType.HOST, text.lower()


def link_assets(
    *,
    engagement_id: str,
    source: str,
    target: str,
    relation: str,
    evidence: str = "",
    confidence: str = "likely",
    run_id: str = "",
    derived_from: list[str] | str | None = None,
) -> dict[str, Any]:
    """Create an operator-named graph edge + durable observation finding."""
    eid = (engagement_id or "").strip()
    if not eid:
        raise ValueError("engagement_id required")

    src_type, src_label = parse_asset_ref(source)
    tgt_type, tgt_label = parse_asset_ref(target)
    conf_s = (confidence or "likely").strip().lower()
    try:
        conf = FindingConfidence(conf_s)
    except ValueError:
        conf = FindingConfidence.LIKELY
        conf_s = conf.value

    rel = sanitize_relation(relation, confidence=conf_s)
    ev = (evidence or "").strip()
    if not ev:
        raise ValueError("evidence is required (why this link exists)")

    edge = get_engagement_graph().operator_link(
        engagement_id=eid,
        source_type=src_type,
        source_label=src_label,
        target_type=tgt_type,
        target_label=tgt_label,
        relationship=rel,
        run_id=run_id or "",
        source_tool="operator_graph_link",
        metadata={"confidence": conf_s, "evidence": ev[:300]},
    )

    from osprey.services.evidence_chain import merge_derived_from, normalize_derived_from

    meta = {
        "source_id": edge["source_id"],
        "target_id": edge["target_id"],
        "relationship": rel,
        "operator_relation": (relation or "").strip()[:80],
        "edge_kind": "hypothesis" if is_hypothesis_relation(rel) else "asserted",
    }
    meta = merge_derived_from(meta, normalize_derived_from(derived_from))
    # No Finding is minted here — this used to also construct one with
    # confidence=conf, a caller-asserted value Plan 03's one law forbids
    # (confidence is computed from evidence, never set by a caller). The
    # edge itself (operator_link above — a disclosed, documented exception
    # in engagement_graph.py's module docstring) is the durable write;
    # its own confidence lives in the edge/node metadata, queryable via
    # platform_graph_query, with no need for a duplicate Finding beside it.

    return {
        "engagement_id": eid,
        "source_id": edge["source_id"],
        "target_id": edge["target_id"],
        "relationship": rel,
        "confidence": conf_s,
        "hypothesis": is_hypothesis_relation(rel),
        "derived_from": meta.get("derived_from") or [],
        "hint": (
            "Hypothesis edge — not proof for COMPLETE/CRITICAL. "
            "Confirm with real evidence, then re-link with confidence=confirmed, "
            "or file_finding once you have evidence to attach."
            if is_hypothesis_relation(rel)
            else "Asserted link stored. Still need confirmed proof for CRITICAL claims."
        ),
    }


def link_assets_many(
    *,
    engagement_id: str,
    evidence: str = "",
    confidence: str = "likely",
    run_id: str = "",
    derived_from: list[str] | str | None = None,
    source: str = "",
    relation: str = "",
    targets: list[str] | None = None,
    links: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Persist many operator-named graph edges in ONE call.

    This is the answer to "35 subdomains means 35 platform_graph_link calls" —
    the platform does not hardcode which relations exist (LLM still names them),
    it only removes the per-edge round-trip cost so bulk persistence is cheap
    enough to actually happen during a live engagement.

    Two input shapes (use whichever fits):
      - Fan form: source= + relation= + targets=[...] — one source, many targets,
        all sharing the same relation/evidence/confidence.
      - List form: links=[{source, target, relation, evidence?, confidence?,
        derived_from?}, ...] — fully independent edges, e.g. mixed relations from
        one tool run (subdomain->ip resolves_to, ip->tech runs_tech, etc).

    Both forms may be combined in one call. Every edge still requires evidence,
    still gets hypothesis_ prefixed when confidence != confirmed — nothing
    about the single-edge evidence contract is relaxed for bulk writes.
    """
    eid = (engagement_id or "").strip()
    if not eid:
        raise ValueError("engagement_id required")

    raw_items: list[dict[str, Any]] = []

    fan_targets = [t for t in (targets or []) if str(t).strip()]
    if fan_targets:
        if not source.strip():
            raise ValueError("source is required when targets= is used")
        if not relation.strip():
            raise ValueError("relation is required when targets= is used")
        for t in fan_targets:
            raw_items.append(
                {
                    "source": source,
                    "target": t,
                    "relation": relation,
                    "evidence": evidence,
                    "confidence": confidence,
                    "derived_from": derived_from,
                }
            )

    for item in links or []:
        raw_items.append(
            {
                "source": str(item.get("source") or ""),
                "target": str(item.get("target") or ""),
                "relation": str(item.get("relation") or ""),
                "evidence": str(item.get("evidence") or evidence or ""),
                "confidence": str(item.get("confidence") or confidence or "likely"),
                "derived_from": item.get("derived_from", derived_from),
            }
        )

    if not raw_items:
        raise ValueError("provide targets= (with source/relation) or links=[...]")
    if len(raw_items) > 500:
        raise ValueError(f"too many edges in one call ({len(raw_items)}); split into batches of <=500")

    from osprey.services.evidence_chain import merge_derived_from, normalize_derived_from

    resolved: list[dict[str, Any]] = []
    graph_edges: list[dict[str, Any]] = []
    all_derived: list[str] = []
    n_confirmed = 0
    n_hypothesis = 0

    for idx, item in enumerate(raw_items):
        src_type, src_label = parse_asset_ref(item["source"])
        tgt_type, tgt_label = parse_asset_ref(item["target"])
        conf_s = (item["confidence"] or "likely").strip().lower()
        try:
            FindingConfidence(conf_s)
        except ValueError:
            conf_s = "likely"
        rel = sanitize_relation(item["relation"], confidence=conf_s)
        ev = (item["evidence"] or "").strip()
        if not ev:
            raise ValueError(f"edge #{idx} ({item['source']} -> {item['target']}): evidence is required")

        is_hyp = is_hypothesis_relation(rel)
        n_hypothesis += int(is_hyp)
        n_confirmed += int(not is_hyp)

        graph_edges.append(
            {
                "source_type": src_type,
                "source_label": src_label,
                "target_type": tgt_type,
                "target_label": tgt_label,
                "relationship": rel,
                "source_tool": "operator_graph_link_many",
                "metadata": {"confidence": conf_s, "evidence": ev[:300]},
            }
        )
        resolved.append(
            {
                "source": f"{src_type.value}:{src_label}",
                "target": f"{tgt_type.value}:{tgt_label}",
                "relationship": rel,
                "confidence": conf_s,
                "hypothesis": is_hyp,
            }
        )
        all_derived.extend(normalize_derived_from(item.get("derived_from")))

    written = get_engagement_graph().operator_link_many(
        engagement_id=eid,
        edges=graph_edges,
        run_id=run_id or "",
    )
    for r, w in zip(resolved, written):
        r["source_id"] = w["source_id"]
        r["target_id"] = w["target_id"]

    sample = "; ".join(f"{r['source']}--{r['relationship']}-->{r['target']}" for r in resolved[:5])
    if len(resolved) > 5:
        sample += f"; …(+{len(resolved) - 5} more)"

    meta = {
        "edge_count": len(resolved),
        "confirmed_count": n_confirmed,
        "hypothesis_count": n_hypothesis,
        "edges": resolved,
    }
    meta = merge_derived_from(meta, all_derived)
    # No Finding is minted here either — see link_assets above for why: a
    # caller-asserted confidence (here, CONFIRMED/HYPOTHESIS picked from
    # whether any edge was a hypothesis) is exactly what Plan 03's one law
    # forbids. The edges themselves are the durable write.

    return {
        "engagement_id": eid,
        "count": len(resolved),
        "confirmed_count": n_confirmed,
        "hypothesis_count": n_hypothesis,
        "edges": resolved,
        "hint": (
            f"Persisted {len(resolved)} edge(s) in one call — "
            f"{n_confirmed} asserted, {n_hypothesis} hypothesis (not proof yet): "
            f"{sample}. This is the natural way to persist a whole tool run's "
            "relationships: don't summarize in chat only, link everything you found."
        ),
    }


def record_think(
    *,
    engagement_id: str,
    hypothesis: str,
    plan: str = "",
    evidence: str = "",
    next_tool: str = "",
    run_id: str = "",
) -> dict[str, Any]:
    """Persist operator thinking as a durable Hypothesis — plans/harness/05-
    world-model-and-attack-paths.md's actual first-class object for "an
    unresolved claim the reasoner is still testing," not a Finding. This used
    to construct a ``Finding`` directly with a hardcoded ``confidence=
    HYPOTHESIS`` — a caller-asserted confidence Plan 03's one law forbids
    (confidence is computed from evidence by ``confidence_for``, never set by
    a caller). A hypothesis was never actually a Finding in the first place;
    routing it through ``hypothesis_store`` instead of contorting it to fit
    the finding law is the complete fix, not a patch around the symptom.
    """
    from osprey.services import hypothesis_store

    eid = (engagement_id or "").strip()
    if not eid:
        raise ValueError("engagement_id required")
    hyp = (hypothesis or "").strip()
    if not hyp:
        raise ValueError("hypothesis required")

    statement_parts = [hyp]
    if plan.strip():
        statement_parts.append(f"Plan: {plan.strip()}")
    if evidence.strip():
        statement_parts.append(f"Evidence: {evidence.strip()}")
    if next_tool.strip():
        statement_parts.append(f"Next: {next_tool.strip()}")
    statement = "\n".join(statement_parts)[:2000]

    stored = hypothesis_store.raise_hypothesis(eid, statement=statement)
    return {
        "engagement_id": eid,
        "hypothesis_id": stored.id,
        "statement": stored.statement,
        "hint": "Hypothesis stored — visible via platform_hypothesis(action='list') / the context packet.",
    }


def apply_script_rel_markers(
    stdout: str,
    *,
    engagement_id: str,
    run_id: str = "",
) -> list[dict[str, Any]]:
    """Apply REL| lines from script stdout into the graph."""
    from osprey.services.parsers.freeform_probe import extract_rel_markers

    results: list[dict[str, Any]] = []
    for item in extract_rel_markers(stdout):
        try:
            results.append(
                link_assets(
                    engagement_id=engagement_id,
                    source=item["source"],
                    target=item["target"],
                    relation=item["relation"],
                    evidence=item["evidence"],
                    confidence=item.get("confidence") or "likely",
                    run_id=run_id,
                )
            )
        except ValueError:
            continue
    return results
