"""Multi-factor, decay-aware prioritization — plans/harness/06-prioritization-
engine.md.

Answers "what's worth doing next" over the world model (Plan 05): assets,
observations, questions, attack paths. Deliberately a DIFFERENT question from
Plan 03's ``confidence_for`` ("is this real") — a low-confidence hypothesis can
still be the highest-priority thing to chase next, and a well-evidenced finding
can be low priority once it's stale or already actioned. Priority never feeds
back into confidence, and confidence never feeds into priority except as one
input (``evidence_strength``).

Each factor is a small pure function reading a ``PriorityContext`` that batches
the expensive world-model/graph/tool-coverage reads ONCE per engagement call
(mirrors ``sufficiency.phase_signals``'s one-query-per-call discipline) instead
of re-querying per scored item.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from osprey.schemas.attack_path import AttackPath
from osprey.schemas.engagement_graph import AssetNode
from osprey.schemas.observation import Observation
from osprey.schemas.priority import PriorityFactors, PriorityScore
from osprey.schemas.reasoning import Question
from osprey.services.config_loader import read_config
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.engagement_store import get_engagement_store
from osprey.services.observation_store import get_observation_store
from osprey.services.target_utils import registrable_apex
from osprey.services.tool_coverage_store import get_tool_coverage_store

logger = logging.getLogger(__name__)

_DEFAULTS: dict[str, Any] = {
    "weights": {
        "objective_relevance": 1.5, "evidence_strength": 1.0, "novelty": 1.0,
        "potential_impact": 1.5, "relationship_centrality": 1.0, "unexplained_behavior": 1.2,
        "validation_potential": 0.8, "coverage_importance": 1.0,
        "cost": 0.6, "repetition": 1.0, "risk": 1.0,
    },
    "observation_types": {},
    "default_observation_type": {"impact": 0.4, "cost": 0.3, "validation_ease": 0.6, "half_life_hours": 48},
    "severity_impact": {"critical": 1.0, "high": 0.75, "medium": 0.45, "low": 0.2, "info": 0.05},
    "phase_thresholds": {"vuln": 1.4, "exploit": 2.2},
    "phase_item_types": {
        "vuln": ["port", "service", "technology", "url", "host", "injection_point", "waf"],
        "exploit": ["scanner_signal", "credential", "secret", "injection_point"],
    },
}

# Observation types whose natural next step tends toward deeper/exploit-
# adjacent probing — a risk bump when the engagement hasn't authorized that.
_INTRUSIVE_FOLLOWUP_TYPES = frozenset({"credential", "secret", "injection_point", "scanner_signal"})


@lru_cache(maxsize=1)
def load_priority_config() -> dict[str, Any]:
    data: dict[str, Any] = {k: (dict(v) if isinstance(v, dict) else list(v) if isinstance(v, list) else v) for k, v in _DEFAULTS.items()}
    raw = read_config("priority.yaml")
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict) and isinstance(data.get(key), dict):
                data[key].update(value)
            else:
                data[key] = value
    return data


def reload_priority_config() -> dict[str, Any]:
    load_priority_config.cache_clear()
    return load_priority_config()


def _obs_type_priors(cfg: dict[str, Any], type_key: str) -> dict[str, float]:
    types = cfg.get("observation_types") or {}
    return types.get(type_key) or cfg.get("default_observation_type") or _DEFAULTS["default_observation_type"]


def _severity_impact(details: dict[str, Any], cfg: dict[str, Any]) -> float | None:
    """The scanner's own claimed severity (details.claimed_severity — parsers
    already extract this, e.g. from a nuclei template's severity field;
    never assigned by this module) as an impact score, or None when the
    observation carries no severity claim at all (a port/technology/etc has
    no such concept). When present, this REPLACES the flat per-type impact
    prior rather than just boosting it — a claimed 'info' result must be
    able to rank below a claimed 'critical' one of the very same
    observation type, not just tie with it."""
    claimed = str(details.get("claimed_severity") or "").strip().lower()
    if not claimed:
        return None
    table = cfg.get("severity_impact") or _DEFAULTS["severity_impact"]
    return table.get(claimed)


def _decay(last_seen_at: datetime | None, first_seen_at: datetime | None, half_life_hours: float, now: datetime) -> float:
    """Exponential decay from recency — 1.0 for something seen this instant,
    0.5 after one half-life, fading toward 0 as it goes stale. Never negative,
    never above 1."""
    anchor = last_seen_at or first_seen_at
    if anchor is None:
        return 1.0
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    age_hours = max(0.0, (now - anchor).total_seconds() / 3600.0)
    hl = max(0.1, float(half_life_hours))
    return math.pow(0.5, age_hours / hl)


@dataclass
class PriorityContext:
    engagement_id: str
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    config: dict[str, Any] = field(default_factory=load_priority_config)
    scope_apexes: set[str] = field(default_factory=set)
    destructive_allowed: bool = True
    node_degree: dict[str, int] = field(default_factory=dict)
    obs_id_to_degree: dict[str, int] = field(default_factory=dict)
    obs_id_to_confidence: dict[str, str] = field(default_factory=dict)
    coverage_gap_node_ids: set[str] = field(default_factory=set)
    unexplained_obs_ids: set[str] = field(default_factory=set)
    conflicted_node_ids: set[str] = field(default_factory=set)
    attempts_by_apex: Counter = field(default_factory=Counter)


def build_context(engagement_id: str) -> PriorityContext:
    """One batch of world-model/graph/coverage reads, reused across every item
    scored for this engagement — the same discipline ``sufficiency.
    phase_signals`` uses for finding counts, extended to the richer world model."""
    eid = (engagement_id or "").strip()
    ctx = PriorityContext(engagement_id=eid)
    if not eid:
        return ctx

    engagement = get_engagement_store().get(eid)
    if engagement is not None:
        from osprey.services.exploit_pipeline import _engagement_scope_apexes

        ctx.scope_apexes = _engagement_scope_apexes(eid, engagement)
        ctx.destructive_allowed = bool(engagement.rules_of_engagement.destructive_actions_allowed)

    graph = get_engagement_graph()
    nodes = graph.list_nodes(engagement_id=eid, limit=20_000)
    edges = graph.list_edges(engagement_id=eid, limit=50_000)
    degree: Counter = Counter()
    for e in edges:
        degree[e.source_id] += 1
        degree[e.target_id] += 1
    ctx.node_degree = dict(degree)

    has_port = {e.source_id for e in edges if e.relationship == "has_port"}
    from osprey.schemas.engagement_graph import AssetType

    for n in nodes:
        if n.asset_type in (AssetType.HOST, AssetType.SUBDOMAIN) and n.id not in has_port:
            ctx.coverage_gap_node_ids.add(n.id)
        if n.conflicts:
            ctx.conflicted_node_ids.add(n.id)
        node_deg = ctx.node_degree.get(n.id, 0)
        for oid in n.observation_ids:
            ctx.obs_id_to_degree[oid] = max(ctx.obs_id_to_degree.get(oid, 0), node_deg)
            ctx.obs_id_to_confidence[oid] = n.confidence

    cited: set[str] = set()
    for n in nodes:
        cited.update(n.observation_ids)
    for e in edges:
        cited.update(e.observation_ids)
    observations = get_observation_store().list_for_engagement(eid, limit=10_000)
    ctx.unexplained_obs_ids = {o.id for o in observations if o.id not in cited}

    for rec in get_tool_coverage_store().list_for_engagement(eid, limit=5000):
        ap = registrable_apex(rec.asset) or (rec.asset or "").strip().lower()
        if ap:
            ctx.attempts_by_apex[ap] += 1

    return ctx


def _weighted_total(cfg: dict[str, Any], factors: PriorityFactors) -> float:
    w = cfg.get("weights") or _DEFAULTS["weights"]
    total = 0.0
    for name in ("objective_relevance", "evidence_strength", "novelty", "potential_impact",
                 "relationship_centrality", "unexplained_behavior", "validation_potential",
                 "coverage_importance"):
        total += float(w.get(name, 1.0)) * getattr(factors, name)
    for name in ("cost", "repetition", "risk"):
        total -= float(w.get(name, 1.0)) * getattr(factors, name)
    return total


def _objective_relevance(target: str, ctx: PriorityContext) -> float:
    apex = registrable_apex(target or "")
    if not apex:
        return 0.5  # no host to judge — neutral, never a hard block
    if not ctx.scope_apexes:
        return 1.0  # nothing discovered as scope yet — don't penalize early items
    return 1.0 if apex in ctx.scope_apexes else 0.0


def _risk(type_key: str, ctx: PriorityContext) -> float:
    if ctx.destructive_allowed:
        return 0.0
    return 0.4 if type_key in _INTRUSIVE_FOLLOWUP_TYPES else 0.0


def _repetition(target: str, ctx: PriorityContext) -> float:
    apex = registrable_apex(target or "") or (target or "").strip().lower()
    if not apex:
        return 0.0
    return min(1.0, ctx.attempts_by_apex.get(apex, 0) / 5.0)


def score_observation(obs: Observation, ctx: PriorityContext) -> PriorityScore:
    cfg = ctx.config
    priors = _obs_type_priors(cfg, obs.type.value)
    decay = _decay(obs.last_seen_at, obs.created_at, priors["half_life_hours"], ctx.now)
    occurrence = obs.occurrence_count or 1
    degree = ctx.obs_id_to_degree.get(obs.id, 0)
    is_unexplained = obs.id in ctx.unexplained_obs_ids
    severity_impact = _severity_impact(obs.details, cfg)
    impact = severity_impact if severity_impact is not None else float(priors["impact"])

    factors = PriorityFactors(
        objective_relevance=_objective_relevance(obs.target, ctx),
        evidence_strength=min(1.0, occurrence / 3.0) * decay,
        novelty=decay,
        potential_impact=impact,
        relationship_centrality=min(1.0, degree / 5.0),
        unexplained_behavior=1.0 if is_unexplained else 0.0,
        validation_potential=float(priors["validation_ease"]),
        coverage_importance=0.0,
        cost=float(priors["cost"]),
        repetition=_repetition(obs.target, ctx),
        risk=_risk(obs.type.value, ctx),
    )
    return PriorityScore(
        item_id=obs.id, item_kind="observation", type_key=obs.type.value, target=obs.target,
        label=(obs.details.get("title") or obs.details.get("url") or obs.details.get("hostname") or obs.target),
        total=_weighted_total(cfg, factors), factors=factors,
    )


def score_asset(node: AssetNode, ctx: PriorityContext) -> PriorityScore:
    cfg = ctx.config
    degree = ctx.node_degree.get(node.id, 0)
    is_gap = node.id in ctx.coverage_gap_node_ids
    has_conflict = node.id in ctx.conflicted_node_ids
    decay = _decay(node.updated_at, node.created_at, 168.0, ctx.now)  # assets default to a 1-week half-life
    # Impact is WHAT the asset is (a credential/secret node matters more than a
    # port node) — the same observation_types impact-prior table score_observation
    # uses, keyed on asset_type instead of observation type (they share most of
    # their vocabulary: credential, secret, service, port, technology, host,
    # subdomain, url all mean the same thing in both tables). This used to be
    # `0.6 if confidence == "likely" else 0.4` — a confidence-tier binary blind to
    # asset_type, so a CREDENTIAL node ranked no higher than a PORT node at the
    # same confidence. Confidence is already scored separately via
    # evidence_strength below; reusing it again here just duplicated that signal
    # while leaving impact unmodeled.
    impact = float(_obs_type_priors(cfg, node.asset_type.value)["impact"])

    factors = PriorityFactors(
        objective_relevance=_objective_relevance(node.label, ctx),
        evidence_strength=min(1.0, len(node.source_tools) / 3.0) * decay,
        novelty=decay,
        potential_impact=impact,
        relationship_centrality=min(1.0, degree / 5.0),
        unexplained_behavior=1.0 if has_conflict else 0.0,
        validation_potential=0.7,
        coverage_importance=1.0 if is_gap else 0.0,
        cost=0.3,
        repetition=_repetition(node.label, ctx),
        risk=0.0,
    )
    return PriorityScore(
        item_id=node.id, item_kind="asset", type_key=getattr(node.asset_type, "value", str(node.asset_type)),
        target=node.label, label=node.label, total=_weighted_total(cfg, factors), factors=factors,
    )


def score_question(q: Question, ctx: PriorityContext) -> PriorityScore:
    cfg = ctx.config
    decay = _decay(q.updated_at, q.created_at, 240.0, ctx.now)
    factors = PriorityFactors(
        objective_relevance=_objective_relevance(q.related_asset_id, ctx) if q.related_asset_id else 0.7,
        evidence_strength=0.0,
        novelty=decay,
        potential_impact=0.5,
        relationship_centrality=min(1.0, ctx.node_degree.get(q.related_asset_id, 0) / 5.0) if q.related_asset_id else 0.0,
        unexplained_behavior=0.6,
        validation_potential=0.5,
        coverage_importance=0.0,
        cost=0.2,
        repetition=0.0,
        risk=0.0,
    )
    return PriorityScore(
        item_id=q.id, item_kind="question", type_key="question", target=q.related_asset_id,
        label=q.text, total=_weighted_total(cfg, factors), factors=factors,
    )


_ATTACK_PATH_STATUS_IMPACT = {"hypothesized": 0.5, "investigating": 0.8, "validated": 1.0, "dead": 0.0}


def score_attack_path(path: AttackPath, ctx: PriorityContext) -> PriorityScore:
    cfg = ctx.config
    decay = _decay(path.updated_at, path.created_at, 240.0, ctx.now)
    status = path.status.value if hasattr(path.status, "value") else str(path.status)
    factors = PriorityFactors(
        objective_relevance=1.0,
        evidence_strength=min(1.0, len(path.steps) / 3.0),
        novelty=decay,
        potential_impact=_ATTACK_PATH_STATUS_IMPACT.get(status, 0.5),
        relationship_centrality=min(1.0, len(path.steps) / 4.0),
        unexplained_behavior=0.0,
        validation_potential=0.6,
        coverage_importance=0.0,
        cost=0.4,
        repetition=0.0,
        risk=0.0,
    )
    return PriorityScore(
        item_id=path.id, item_kind="attack_path", type_key=status, target="",
        label=path.title, total=_weighted_total(cfg, factors), factors=factors,
    )


_ALL_KINDS = ("observation", "asset", "question", "attack_path")


def top_priorities(
    engagement_id: str, *, kinds: tuple[str, ...] = _ALL_KINDS, limit: int = 20,
    ctx: PriorityContext | None = None,
) -> list[PriorityScore]:
    """The ranked list every consumer (context packet, CLI, MCP, phase gating)
    reads — a fresh computation each call, never a cached ranking, since
    novelty/evidence_strength decay with real time."""
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    ctx = ctx or build_context(eid)
    scored: list[PriorityScore] = []

    if "observation" in kinds:
        for o in get_observation_store().list_for_engagement(eid, limit=5000):
            scored.append(score_observation(o, ctx))
    if "asset" in kinds:
        for n in get_engagement_graph().list_nodes(engagement_id=eid, limit=5000):
            scored.append(score_asset(n, ctx))
    if "question" in kinds:
        from osprey.services import question_store

        for q in question_store.list_open(eid):
            scored.append(score_question(q, ctx))
    if "attack_path" in kinds:
        from osprey.services import attack_path_store

        for p in attack_path_store.list_active(eid):
            scored.append(score_attack_path(p, ctx))

    scored.sort(key=lambda s: s.total, reverse=True)
    return scored[: max(1, limit)]


def phase_priority(engagement_id: str, phase: str, *, ctx: PriorityContext | None = None) -> tuple[float, str]:
    """Max score among observations whose type feeds ``phase`` — Step 3: one
    hot lead is reason enough, matching the plan's own reasoning that an
    unexplained high-centrality observation can outrank a coverage gap."""
    eid = (engagement_id or "").strip()
    ctx = ctx or build_context(eid)
    cfg = ctx.config
    wanted_types = set((cfg.get("phase_item_types") or {}).get(phase) or [])
    if not wanted_types or not eid:
        return 0.0, ""
    best: PriorityScore | None = None
    for o in get_observation_store().list_for_engagement(eid, limit=5000):
        if o.type.value not in wanted_types:
            continue
        s = score_observation(o, ctx)
        if best is None or s.total > best.total:
            best = s
    if best is None:
        return 0.0, ""
    return best.total, f"{best.type_key} '{best.label}' priority={best.total:.2f}"


def should_unlock_phase(engagement_id: str, phase: str, *, ctx: PriorityContext | None = None) -> tuple[bool, str]:
    """Replaces ``sufficiency.should_trigger``/``trigger_reason``'s finding-
    count thresholds (Plan 06 Step 4) — a phase unlocks when the world model
    has an item whose priority for that area crosses ``phase_thresholds``,
    not when a count of findings crosses a hardcoded number."""
    eid = (engagement_id or "").strip()
    ctx = ctx or build_context(eid)
    threshold = float((ctx.config.get("phase_thresholds") or {}).get(phase, 0.0))
    score, reason = phase_priority(eid, phase, ctx=ctx)
    unlocked = score >= threshold if threshold > 0 else False
    if unlocked:
        return True, f"{reason} >= threshold {threshold:.2f}"
    return False, f"best {phase} priority {score:.2f} < threshold {threshold:.2f}"
