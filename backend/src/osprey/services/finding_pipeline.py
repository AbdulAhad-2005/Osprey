"""The earned-finding pipeline — plans/harness/03-earned-finding-pipeline.md.

A ``Finding`` comes into existence exactly ONE way (plan 19 Phase 6), obeying
the one law (``confidence = f(evidence)``, computed by ``services.confidence.
confidence_for``, never asserted by a caller):

- ``file_finding`` — explicit filing by a brain (an LLM/agent/human) *after*
  gathering evidence. The signature has no ``confidence`` parameter at all —
  there is nothing for a caller to assert.

The former ``promote_observations`` ("Pentest-Swarm" deterministic promotion)
was deleted: it minted a VULNERABILITY finding from every SCANNER_SIGNAL
observation on a corroboration COUNT alone, the "truth from counts"
anti-pattern. A scanner match now stays a scanner_claim observation; a human/
LLM turns it into a conclusion via ``file_finding`` with real evidence, and the
report surfaces unverified claims in a dedicated section (report_generator /
markdown_report) without minting findings.

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
    is_conclusion_type,
)
from osprey.schemas.fp_cache import FpPattern
from osprey.schemas.observation import Observation, observation_signature
from osprey.services import fp_cache, suppressed_promotion_store
from osprey.services.confidence import confidence_for, evidence_summary_for
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.evidence_grounding import ground_claim
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
    # A finding is a brain's evidence-backed CONCLUSION, never a structural
    # fact (plan 19 Phase 7). A subdomain/host/url/port/service/technology/
    # osint-entity/raw observation belongs in the observation store + asset
    # graph — it is a fact, not a judgment. Rejecting it here (the one
    # admission path) is what makes "only a brain writes a conclusion, never a
    # structural fact" structural instead of a convention. (is_conclusion_type
    # lives in schemas/finding.py, not this module, so the no-type-branching
    # confidence gate — scripts/lint_no_type_branching.py — is untouched: this
    # is admission scope, not confidence scope.)
    if not is_conclusion_type(finding_type):
        raise FileFindingError(
            f"{getattr(finding_type, 'value', finding_type)!r} is a structural/observed fact, "
            "not a conclusion — record it as an Observation (it already auto-ingests), never a "
            "finding. A finding is only ever a brain's evidence-backed security judgment "
            "(vulnerability / access / credential / secret)."
        )

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

    # Ground every REPRODUCTION or VERIFICATION claim against real,
    # already-recorded tool output before it's allowed anywhere near
    # confidence_for() — see evidence_grounding.py. Both kinds claim a
    # machine-checkable artifact backs them (a PoC re-run, a direct
    # config/permission read); ATTESTATION is deliberately excluded — it
    # exists precisely for vouching WITHOUT one. Without this, evidence that
    # only proves a narrower fact than the finding's actual claim (e.g. "this
    # software version is present" attached to a finding titled "this CVE
    # applies") rides straight to CONFIRMED on a fact it never established.
    # Defaults a blank observation_id to the first resolved observation so
    # this backstops callers that bypass the MCP layer's own default too,
    # not just platform_file_finding's.
    _GROUNDED_KINDS = {EvidenceRecordKind.REPRODUCTION, EvidenceRecordKind.VERIFICATION}
    by_id = {o.id: o for o in observations}
    for er in records:
        if er.kind not in _GROUNDED_KINDS:
            continue
        target_obs = by_id.get(er.observation_id) or observations[0]
        grounded, reason = ground_claim(er.detail, target_obs, kind=er.kind.value)
        if not grounded:
            raise FileFindingError(f"evidence_kind='{er.kind.value}' rejected: {reason}")

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


# promote_observations() was deleted here (plan 19 Phase 6). It was the
# "Pentest-Swarm" deterministic launderer: it turned every SCANNER_SIGNAL
# observation into a VULNERABILITY finding, reaching CONFIRMED on nothing but a
# corroboration COUNT (two tools agreeing) — the "truth from counts" anti-pattern
# the whole plan exists to kill. A scanner match is a scanner_claim observation
# and stays one; only a brain, via file_finding() citing real evidence, turns it
# into a conclusion. Scanner claims are surfaced to the human honestly through the
# report's dedicated "Scanner Claims (UNVERIFIED)" section (report_generator /
# markdown_report), not by minting findings.


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
