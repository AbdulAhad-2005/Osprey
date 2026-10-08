"""Tech dispatch — signal → task suggestions from observations + graph.

Reads the OBSERVATION store and the asset graph, never ``findings_store``
(plan 19 Phase 2). A dispatch rule fires on the mechanical facts a tool run
produced — a TECHNOLOGY observation, a URL observation, an injection-point
tag, a live host in the graph — not on a *finding*, because in the no-LLM
path no structural finding is ever created (plans/harness/19a): the finding
store held only promoted vulnerabilities, so keying dispatch off it meant the
whole vuln pipeline (nuclei/wpscan/sqlmap/graphql) silently never fired
without an LLM back-filling findings. Sourcing from observations is what lets
the deterministic floor reach vulnerability analysis on its own.

``ObservationType`` values (technology/url/port/service/subdomain/host/...)
line up 1:1 with the rule vocabulary's ``finding_type`` names, so a rule like
``finding_type: technology`` now matches TECHNOLOGY observations, and
``metadata_key: technology`` reads the observation's ``details``. The rule
grammar is unchanged (its redesign into a typed capability policy is Phase 3);
only the source of truth moved.

Plan 18 Workstream B semantics are preserved: a rule declaring
``scope: per_match`` yields one ``DispatchSuggestion`` per matching observation,
carrying that observation's ``target`` as ``subject_id`` and, with
``params_from``, its field values mapped into dispatch params.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from osprey.schemas.hybrid import DispatchSuggestion
from osprey.schemas.observation import Observation, ObservationType
from osprey.services.config_loader import read_config_layered
from osprey.services.config_validation import ConfigValidationError, validate_tech_dispatch
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.observation_store import get_observation_store

logger = logging.getLogger(__name__)

# Observation types that count as "a live host has been probed" / "subdomains
# enumerated" for a phases_complete clause — the mechanical evidence those
# phases leave behind, read from observations instead of finding-type counts.
_PHASE_EVIDENCE: dict[str, ObservationType] = {
    "subdomain_enumeration": ObservationType.SUBDOMAIN,
    "live_host_probing": ObservationType.URL,
}


# Last config that validated clean — kept so a malformed hot-reloaded edit
# falls back to it (G3 last-known-good) instead of crashing the engine.
_LAST_GOOD: dict[str, Any] = {"signals": []}


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    # Layered so an operator can add/edit/remove checks via tech_dispatch.local
    # .yaml with no core-code change (G2); validated loudly so a malformed edit
    # names its offending field instead of silently no-opping (G1); and on a bad
    # edit the last valid config is retained, never half-applied (G3).
    global _LAST_GOOD
    data = read_config_layered("tech_dispatch.yaml") or {"signals": []}
    try:
        _LAST_GOOD = validate_tech_dispatch(data)
    except ConfigValidationError:
        logger.exception("tech_dispatch.yaml rejected — keeping last-known-good config")
    return _LAST_GOOD


def suggest_dispatch(
    *,
    engagement_id: str = "",
    run_id: str = "",
    phase: str | None = None,
) -> list[DispatchSuggestion]:
    observations = get_observation_store().list_for_engagement(engagement_id)
    graph = get_engagement_graph().summary(engagement_id=engagement_id, run_id=run_id)
    suggestions: list[DispatchSuggestion] = []

    for rule in _load().get("signals", []):
        match = rule.get("match", {})
        dispatch = rule.get("dispatch", {})
        if not dispatch:
            continue

        matched, per_match_obs = _matches(match, observations, graph, engagement_id)
        if not matched:
            continue

        base = {
            "signal": str(rule.get("id", "")),
            "task_id": str(dispatch.get("task_id", "")),
            "default_tool": str(dispatch.get("default_tool", "")),
            "alternatives": list(dispatch.get("alternatives") or []),
            "skill_file": str(dispatch.get("skill_file", "")),
            "reason": str(dispatch.get("reason", "")),
            "priority": int(dispatch.get("priority", 0)),
            "additional_args": str(dispatch.get("additional_args", "")),
        }

        if match.get("scope") == "per_match" and per_match_obs:
            params_from = dispatch.get("params_from") or {}
            # Dedup by subject: several observations on the same host must not
            # produce duplicate suggestions for that host.
            seen_subjects: set[str] = set()
            for o in per_match_obs:
                subject = (o.target or "").strip()
                if not subject or subject in seen_subjects:
                    continue
                seen_subjects.add(subject)
                params = {
                    str(param_key): str(_observation_field(o, field_name))
                    for param_key, field_name in params_from.items()
                    if _observation_field(o, field_name)
                }
                suggestions.append(DispatchSuggestion(**base, subject_id=subject, params=params))
        else:
            suggestions.append(DispatchSuggestion(**base))

    suggestions.sort(key=lambda s: s.priority, reverse=True)
    return suggestions


def _observation_field(observation: Observation, field_name: str) -> str:
    """Resolve a ``params_from`` source field against an observation: ``target``
    is the top-level attribute; ``title`` falls back through details then target;
    anything else is looked up in ``details`` (where parsers stash technology,
    url, hostname, port, cve, template_id, …)."""
    if field_name == "target":
        return str(observation.target or "")
    if field_name == "title":
        return str(observation.details.get("title") or observation.target or "")
    return str(observation.details.get(field_name, "") or "")


def _matches(
    match: dict[str, Any],
    observations: list[Observation],
    graph,
    engagement_id: str,
) -> tuple[bool, list[Observation]]:
    """Returns (matched, per_match_observations). ``per_match_observations`` is
    populated for a rule whose clause identifies specific observations
    (finding_type/has_tag/metadata_key); a purely aggregate/relational clause
    (graph_query, has_live_hosts, phases_complete, or a type used only as a
    count threshold) has no single subject and returns an empty list.
    """
    per_match: list[Observation] = []

    # ``finding_type`` is the rule vocabulary name; it selects observations of
    # the matching ObservationType (the enum values are identical strings).
    otype = match.get("finding_type")
    if otype:
        typed = [o for o in observations if o.type.value == otype]
        min_count = int(match.get("min_count", 1))
        max_count = match.get("max_count")
        if len(typed) < min_count:
            return False, []
        if max_count is not None and len(typed) > int(max_count):
            return False, []
        per_match = typed

    missing = match.get("missing_finding_type")
    if missing:
        if any(o.type.value == missing for o in observations):
            return False, []

    # Match on an observation tag (e.g. injection_point_candidate) with a min count.
    tag = match.get("has_tag")
    if tag:
        min_tagged = int(match.get("min_count", 1))
        tagged = [o for o in observations if tag in (o.tags or [])]
        if len(tagged) < min_tagged:
            return False, []
        per_match = tagged

    # ``metadata_key`` reads the observation's ``details`` (where parsers put
    # technology/version/etc.), the observation-world equivalent of a finding's
    # metadata.
    meta_key = match.get("metadata_key")
    if meta_key:
        meta_contains = match.get("metadata_contains", "").lower()
        meta_value = str(match.get("metadata_value", ""))
        meta_contains_any = [str(x).lower() for x in (match.get("metadata_contains_any") or [])]
        existence_only = not meta_contains and not meta_value and not meta_contains_any
        matched_meta: list[Observation] = []
        for o in observations:
            val = str(o.details.get(meta_key, "")).lower()
            if existence_only:
                if val:
                    matched_meta.append(o)
                continue
            if meta_contains and meta_contains in val:
                matched_meta.append(o)
            elif meta_contains_any and any(sub in val for sub in meta_contains_any):
                matched_meta.append(o)
            elif meta_value and val == meta_value.lower():
                matched_meta.append(o)
        if not matched_meta:
            return False, []
        per_match = matched_meta

    if match.get("graph_query") == "siblings_same_ip":
        min_siblings = int(match.get("min_siblings", 2))
        found_siblings = False
        for sub in graph.subdomains[:10]:
            sib = get_engagement_graph().siblings_same_ip(sub, engagement_id=engagement_id)
            if len(sib.siblings) >= min_siblings:
                found_siblings = True
                break
        if not found_siblings:
            return False, []

    if match.get("has_live_hosts") and not graph.live_hosts:
        return False, []

    phases_complete = match.get("phases_complete")
    if phases_complete:
        present_types = {o.type for o in observations}
        for phase in phases_complete:
            evidence_type = _PHASE_EVIDENCE.get(phase)
            if evidence_type is None or evidence_type not in present_types:
                return False, []

    if match.get("scope") != "per_match":
        return True, []
    return True, per_match
