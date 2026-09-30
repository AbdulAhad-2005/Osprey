"""Tech dispatch — signal → task suggestions from graph + findings.

Plan 18 Workstream B: a rule declaring ``scope: per_match`` yields one
``DispatchSuggestion`` per finding that satisfied its match clause, each
carrying that finding's ``target`` as ``subject_id`` (so the caller can
attach the tool call to the actual host that matched, not the engagement
seed) and, when the rule declares ``params_from``, the matched finding's
field values mapped into dispatch params (e.g. an email-enrichment rule
pulling the matched EMAIL finding's title into ``{"email": ...}``). A rule
with no ``scope`` declared keeps its exact pre-Plan-18 behavior — one
engagement-wide suggestion, empty subject_id/params, resolved by the caller
to the session/seed target — this is purely additive, not a breaking change
to any rule that hasn't been reviewed and annotated yet.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from osprey.schemas.finding import Finding, FindingType
from osprey.schemas.hybrid import DispatchSuggestion
from osprey.services.config_loader import read_config
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.findings_store import get_findings_store

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    data = read_config("tech_dispatch.yaml")
    return data or {"signals": []}


def suggest_dispatch(
    *,
    engagement_id: str = "",
    run_id: str = "",
    phase: str | None = None,
) -> list[DispatchSuggestion]:
    findings = get_findings_store().list(engagement_id=engagement_id, run_id=run_id, limit=500)
    graph = get_engagement_graph().summary(engagement_id=engagement_id, run_id=run_id)
    suggestions: list[DispatchSuggestion] = []

    for rule in _load().get("signals", []):
        match = rule.get("match", {})
        dispatch = rule.get("dispatch", {})
        if not dispatch:
            continue

        matched, per_match_findings = _matches(match, findings, graph, engagement_id)
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

        if match.get("scope") == "per_match" and per_match_findings:
            params_from = dispatch.get("params_from") or {}
            # Dedup by subject: several findings on the same host must not
            # produce duplicate suggestions for that host.
            seen_subjects: set[str] = set()
            for f in per_match_findings:
                subject = (f.target or "").strip()
                if not subject or subject in seen_subjects:
                    continue
                seen_subjects.add(subject)
                params = {
                    str(param_key): str(_finding_field(f, field_name))
                    for param_key, field_name in params_from.items()
                    if _finding_field(f, field_name)
                }
                suggestions.append(DispatchSuggestion(**base, subject_id=subject, params=params))
        else:
            suggestions.append(DispatchSuggestion(**base))

    suggestions.sort(key=lambda s: s.priority, reverse=True)
    return suggestions


def _finding_field(finding: Finding, field_name: str) -> str:
    """Resolve a ``params_from`` source field: ``title``/``target`` are
    top-level Finding attributes; anything else is looked up in metadata."""
    if field_name in ("title", "target"):
        return str(getattr(finding, field_name, "") or "")
    return str(finding.metadata.get(field_name, "") or "")


def _matches(
    match: dict[str, Any],
    findings: list,
    graph,
    engagement_id: str,
) -> tuple[bool, list]:
    """Returns (matched, per_match_findings). ``per_match_findings`` is only
    populated for a rule whose match clause identifies specific findings
    (finding_type/has_tag/metadata_key) — a purely aggregate/relational
    clause (graph_query, has_live_hosts, phases_complete, or a finding_type
    check used only as a count threshold) has no single subject and always
    returns an empty list, exactly like the pre-Plan-18 boolean-only check.
    """
    per_match: list = []

    ftype = match.get("finding_type")
    if ftype:
        typed = [f for f in findings if f.finding_type.value == ftype]
        min_count = int(match.get("min_count", 1))
        max_count = match.get("max_count")
        if len(typed) < min_count:
            return False, []
        if max_count is not None and len(typed) > int(max_count):
            return False, []
        per_match = typed

    missing = match.get("missing_finding_type")
    if missing:
        if any(f.finding_type.value == missing for f in findings):
            return False, []

    # Match on a finding tag (e.g. injection_point_candidate) with a min count.
    tag = match.get("has_tag")
    if tag:
        min_tagged = int(match.get("min_count", 1))
        tagged = [f for f in findings if tag in (f.tags or [])]
        if len(tagged) < min_tagged:
            return False, []
        per_match = tagged

    meta_key = match.get("metadata_key")
    if meta_key:
        meta_contains = match.get("metadata_contains", "").lower()
        meta_value = str(match.get("metadata_value", ""))
        # metadata_contains_any: match if the value contains ANY of these
        # substrings (e.g. [react, vue, angular]). Without this, a rule using it
        # silently fell through to the existence check below and fired on ANY
        # finding carrying the key at all — e.g. `technology_react_or_vue` firing
        # on an Apache host — because meta_contains/meta_value were both empty.
        meta_contains_any = [str(x).lower() for x in (match.get("metadata_contains_any") or [])]
        # No contains/value/any → treat as an existence check (any finding whose
        # metadata carries a non-empty value for this key).
        existence_only = not meta_contains and not meta_value and not meta_contains_any
        matched_meta: list = []
        for f in findings:
            val = str(f.metadata.get(meta_key, "")).lower()
            if existence_only:
                if val:
                    matched_meta.append(f)
                continue
            if meta_contains and meta_contains in val:
                matched_meta.append(f)
            elif meta_contains_any and any(sub in val for sub in meta_contains_any):
                matched_meta.append(f)
            elif meta_value and val == meta_value.lower():
                matched_meta.append(f)
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
        # heuristic: task ids implied by finding types present
        task_signals = {
            "subdomain_enumeration": any(f.finding_type == FindingType.SUBDOMAIN for f in findings),
            "live_host_probing": any(f.finding_type == FindingType.URL for f in findings),
        }
        for phase in phases_complete:
            if not task_signals.get(phase, False):
                return False, []

    if match.get("scope") != "per_match":
        return True, []
    return True, per_match
