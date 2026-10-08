"""The one law — plans/harness/03-earned-finding-pipeline.md.

    A finding's confidence is a pure function of the evidence attached to it.
    You raise confidence by attaching more evidence — never by asserting it.

``confidence_for`` is the *only* place in the codebase that decides a
finding's confidence. It reads evidence records and corroborating source
tools — never ``finding.type``, never a vuln class, never a per-tool rule
table. A finding type invented tomorrow flows through this exact same
function with no code change; that is what makes the failure class this
plan exists to kill ("501 became a finding") structurally impossible to
reintroduce, rather than merely avoided this time.

CI lint gate (Step 7) forbids ``finding_type ==`` / ``switch(type)`` in this
module and every other module in the finding-creation/evidence-capability
path — see scripts/lint_no_type_branching.py.

RECHECK_FAILED (``services.finding_reverification``): evidence is append-only,
so a failed recheck never edits a past confirming record. It only changes the
CURRENT read: if the most recent NOT_REPRODUCED recheck is newer than the most
recent confirming record, CONFIRMED drops to LIKELY (a later successful
re-verification clears it). An INCONCLUSIVE recheck (target unreachable/timeout)
learns nothing and never moves confidence.
"""

from __future__ import annotations

from osprey.schemas.finding import EvidenceRecord, EvidenceRecordKind, FindingConfidence, RecheckReason

# A machine-checkable artifact confirms outright: an actual reproduction or a
# direct config/permission read (both grounded against real tool output at file
# time). Neither is type-specific. ATTESTATION confirms ONLY when it carries
# human provenance (B0) — an agent vouching for itself is not evidence.
_GROUNDED_CONFIRMING = frozenset(
    {EvidenceRecordKind.REPRODUCTION, EvidenceRecordKind.VERIFICATION}
)


def _is_confirming(er: EvidenceRecord) -> bool:
    if er.kind in _GROUNDED_CONFIRMING:
        return True
    return er.kind == EvidenceRecordKind.ATTESTATION and er.human


def confidence_for(
    evidence_records: list[EvidenceRecord] | None,
    *,
    source_tools: list[str] | None = None,
) -> FindingConfidence:
    """Compute confidence from evidence alone.

    - a reproduction, a direct verification, or a HUMAN attestation → CONFIRMED
      — UNLESS the most recent active RECHECK_FAILED is newer than the most
      recent confirming record, in which case → LIKELY.
    - >=2 independent source tools, or an explicit corroboration record → LIKELY
    - anything else (raw signal, or agent-only attestation) → HYPOTHESIS
    """
    records = evidence_records or []
    tools: set[str] = {t.strip() for t in (source_tools or []) if t and t.strip()}
    has_confirming = False
    latest_confirming_at = None
    latest_recheck_failed_at = None
    has_corroboration = False
    for er in records:
        if er.source_tool and er.source_tool.strip():
            tools.add(er.source_tool.strip())
        if _is_confirming(er):
            has_confirming = True
            if latest_confirming_at is None or er.created_at > latest_confirming_at:
                latest_confirming_at = er.created_at
        elif er.kind == EvidenceRecordKind.CORROBORATION:
            has_corroboration = True
        elif er.kind == EvidenceRecordKind.RECHECK_FAILED:
            # Only an active non-reproduction downgrades. An inconclusive recheck
            # (target unreachable/timeout) learns nothing, so it never moves
            # confidence. Legacy records (no reason) keep the old downgrading
            # behavior rather than silently un-downgrading something.
            if er.reason == RecheckReason.INCONCLUSIVE.value:
                continue
            if latest_recheck_failed_at is None or er.created_at > latest_recheck_failed_at:
                latest_recheck_failed_at = er.created_at

    if has_confirming:
        stale = (
            latest_recheck_failed_at is not None
            and (latest_confirming_at is None or latest_recheck_failed_at > latest_confirming_at)
        )
        return FindingConfidence.LIKELY if stale else FindingConfidence.CONFIRMED
    if len(tools) >= 2 or has_corroboration:
        return FindingConfidence.LIKELY
    return FindingConfidence.HYPOTHESIS


def evidence_summary_for(evidence_records: list[EvidenceRecord] | None) -> str:
    """Short human-readable digest of what backs a finding — display only,
    never fed back into ``confidence_for``."""
    records = evidence_records or []
    if not records:
        return "No corroborating evidence beyond the raw signal."
    by_kind: dict[str, int] = {}
    for er in records:
        by_kind[er.kind.value] = by_kind.get(er.kind.value, 0) + 1
    parts = [f"{count} {kind}" for kind, count in sorted(by_kind.items())]
    return "Evidence: " + ", ".join(parts) + "."
