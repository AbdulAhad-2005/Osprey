"""The earned-finding pipeline — plans/harness/03-earned-finding-pipeline.md.

A ``Finding`` comes into existence exactly two ways, both obeying the one
law (``confidence = f(evidence)``, computed by ``services.confidence.
confidence_for``, never asserted by a caller):

- ``file_finding`` — explicit filing (Strix model). An LLM/agent/human calls
  this *after* gathering evidence. The signature has no ``confidence``
  parameter at all — there is nothing for a caller to assert.
- ``promote_observations`` — deterministic promotion (Pentest-Swarm model),
  the no-LLM route. Clusters SCANNER_SIGNAL observations, reads whatever
  corroboration already exists (distinct source_tools that independently
  reported the same observation), and lets ``confidence_for`` compute
  confidence from that. Destructive PoC is never auto-run here.

CI lint gate (Step 7, scripts/lint_no_type_branching.py) forbids
``finding_type ==`` / ``switch(type)`` in this module — nothing here may
branch on what KIND of finding it is building, only on the evidence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from osprey.schemas.finding import (
    ClaimSeverity,
    EvidenceRecord,
    EvidenceRecordKind,
    Finding,
    FindingType,
)
from osprey.schemas.fp_cache import FpPattern
from osprey.schemas.observation import Observation, ObservationType, observation_signature
from osprey.services import fp_cache, suppressed_promotion_store
from osprey.services.confidence import confidence_for, evidence_summary_for
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store

logger = logging.getLogger(__name__)


class FileFindingError(ValueError):
    """Raised when file_finding is called without the evidence it requires."""


@dataclass
class FileFindingResult:
    """``finding`` is None exactly when an FP-cache pattern suppressed this
    candidate — ``suppressed_reason`` carries why, so callers never have to
    re-derive it (or re-run the match themselves)."""

    finding: Finding | None
    suppressed_reason: str = ""


def _observation_evidence_text(observations: list[Observation]) -> str:
    parts = []
    for o in observations[:10]:
        label = o.details.get("title") or o.details.get("url") or o.details.get("hostname") or o.target
        parts.append(f"[{o.type.value}] {label}".strip())
    return "; ".join(p for p in parts if p)[:2000]


def file_finding(
    *,
    engagement_id: str,
    title: str,
    finding_type: FindingType,
    observation_ids: list[str],
    claim_severity: ClaimSeverity = ClaimSeverity.NONE,
    description: str = "",
    evidence_records: list[EvidenceRecord] | None = None,
    run_id: str = "",
    target: str = "",
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> FileFindingResult:
    """File a finding backed by evidence. There is no ``confidence=``
    parameter — the caller attaches evidence (``observation_ids``,
    ``evidence_records``) and ``confidence_for`` computes the rest. A caller
    who "knows" this is confirmed but has no reproduction/verification/
    attestation record to show for it gets exactly the confidence that
    evidence earns — say-so is not evidence.

    ``result.finding`` is ``None`` (not an exception) when an FP-cache
    pattern matches this candidate (plans/harness/04-learning-fp-cache.md
    Step 2) — the attempt is recorded in the suppressed-promotion audit
    trail, never silently gone.
    """
    ids = [oid for oid in (observation_ids or []) if oid and oid.strip()]
    if not ids:
        raise FileFindingError(
            "file_finding requires at least one observation_id — a finding must be about "
            "something observed. Extract/record an Observation first."
        )

    store = get_observation_store()
    observations = [o for o in (store.get(oid) for oid in ids) if o is not None]
    if not observations:
        raise FileFindingError(
            f"None of the given observation_ids resolve to a real observation: {ids}"
        )

    resolved_target = target or observations[0].target
    signatures = [observation_signature(o) for o in observations]
    fp_hit = fp_cache.matches(
        target=resolved_target,
        finding_type=finding_type.value,
        title=title,
        observation_signatures=signatures,
    )
    if fp_hit is not None:
        reason = fp_hit.reason or "matched FP-cache pattern"
        suppressed_promotion_store.record(
            engagement_id=engagement_id,
            observation_id=ids[0],
            pattern_id=fp_hit.id,
            title=title,
            reason=reason,
        )
        logger.info("file_finding suppressed by FP-cache pattern %s: %s", fp_hit.id, title)
        return FileFindingResult(finding=None, suppressed_reason=reason)

    # Union each observation's own source_tool with every distinct tool that
    # has independently reported it across occurrences (a merged/corroborated
    # canonical observation's own .source_tool field only reflects the most
    # recent writer — the occurrence history is where corroboration lives).
    tool_set: set[str] = set()
    for o in observations:
        if o.source_tool:
            tool_set.add(o.source_tool)
        tool_set.update(store.distinct_source_tools(o.id))
    source_tools = sorted(tool_set)
    records = list(evidence_records or [])
    confidence = confidence_for(records, source_tools=source_tools)

    finding = Finding(
        engagement_id=engagement_id,
        run_id=run_id,
        finding_type=finding_type,
        title=title[:300],
        description=description,
        evidence=_observation_evidence_text(observations),
        confidence=confidence,
        claim_severity=claim_severity,
        source_tool=source_tools[0] if source_tools else "",
        target=resolved_target,
        tags=list(tags or []),
        metadata=dict(metadata or {}),
        observation_ids=ids,
        source_tools=source_tools,
        evidence_records=records,
        evidence_summary=evidence_summary_for(records),
    )
    stored = get_findings_store().add(finding)
    try:
        get_engagement_graph().ingest_finding(stored)
    except Exception:  # noqa: BLE001
        logger.debug("Graph ingest skipped for filed finding %s", stored.id, exc_info=True)
    return FileFindingResult(finding=stored)


# Observation types this deterministic pass considers — a scanner/tool
# signal is exactly the "may be a vuln, not yet judged" bucket Plan 02's
# parsers produce (nuclei template match, nmap NSE vulners/vulns.lua hit,
# a subdomain-takeover check, a Shodan CVE tag, …). Widening promotion to
# other observation types (credentials, DNSSEC/SPF posture, …) is a later,
# separately-scoped pass — not silently expanding this list is deliberate.
_PROMOTABLE_TYPES = frozenset({ObservationType.SCANNER_SIGNAL})


def promote_observations(engagement_id: str, *, run_id: str = "") -> list[Finding]:
    """The no-LLM route: for every SCANNER_SIGNAL observation in the
    engagement, attach whatever corroboration already exists (distinct
    source_tools that independently reported the same observation) and file
    a finding via the exact same evidence law as ``file_finding``. Nothing
    here invokes a destructive PoC capability — a finding reaches CONFIRMED
    through this path only if two+ tools corroborated it; a single-source
    signal still becomes a finding, honestly graded HYPOTHESIS, rather than
    getting dropped or inflated.
    """
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    obs_store = get_observation_store()
    promoted: list[Finding] = []

    for otype in _PROMOTABLE_TYPES:
        for obs in obs_store.list_by_type(eid, otype):
            tools = obs_store.distinct_source_tools(obs.id)
            records: list[EvidenceRecord] = []
            if len(tools) >= 2:
                records.append(
                    EvidenceRecord(
                        kind=EvidenceRecordKind.CORROBORATION,
                        source_tool=tools[1],
                        observation_id=obs.id,
                        detail=f"Independently reported by {len(tools)} tools: {', '.join(tools)}",
                    )
                )
            title = str(obs.details.get("title") or obs.details.get("claim") or obs.target or obs.type.value)
            severity_raw = str(obs.details.get("claimed_severity") or "none")
            try:
                severity = ClaimSeverity(severity_raw)
            except ValueError:
                severity = ClaimSeverity.NONE
            try:
                result = file_finding(
                    engagement_id=eid,
                    run_id=run_id,
                    title=title,
                    finding_type=FindingType.VULNERABILITY,
                    observation_ids=[obs.id],
                    claim_severity=severity,
                    description=str(obs.details.get("description") or ""),
                    evidence_records=records,
                    target=obs.target,
                    tags=list(obs.tags or []) + ["promoted"],
                    metadata={"promoted_from_observation": obs.id, **{
                        k: v for k, v in obs.details.items() if k in ("cve", "template_id", "signature")
                    }},
                )
            except FileFindingError as exc:
                logger.debug("promote_observations skipped %s: %s", obs.id, exc)
                continue
            # result.finding is None when an FP-cache pattern suppressed it —
            # already recorded in the suppressed-promotion audit trail.
            if result.finding is not None:
                promoted.append(result.finding)
    return promoted


class MarkFalsePositiveError(ValueError):
    """Raised when mark_false_positive is given an unknown finding_id."""


def mark_false_positive(
    finding_id: str,
    *,
    reason: str = "",
    marked_by: str = "operator",
    target_glob: str = "",
) -> FpPattern:
    """Learn a noise pattern once, apply it forever — plans/harness/04-
    learning-fp-cache.md Step 3. Appends a pattern keyed on the finding's own
    (finding_type, title) and retracts the finding from the CURRENT
    engagement. The pattern — not this deletion — is what prevents the same
    signal from being promoted again on a future replay/scan; the underlying
    Observations/Evidence are never touched (Step 4).

    target_glob scopes the pattern. Left empty (the default), it scopes to
    THIS finding's own target only — marking noise on host A can never
    suppress the same-titled signal on host B by accident. An operator who
    deliberately knows a pattern is noise everywhere (e.g. a scanner's own
    banner) passes an explicit glob ("*" or "*.internal.corp") to widen it;
    that is an opt-in, not a default.
    """
    finding = get_findings_store().get(finding_id)
    if finding is None:
        raise MarkFalsePositiveError(f"no finding with id '{finding_id}'")
    scope = (target_glob or "").strip() or finding.target or "*"
    pattern = fp_cache.add_pattern(
        target_glob=scope,
        finding_type=finding.finding_type.value,
        title_contains=finding.title,
        reason=reason,
        marked_by=marked_by,
    )
    get_findings_store().delete(finding_id=finding_id)
    return pattern
