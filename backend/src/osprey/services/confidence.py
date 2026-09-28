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

RECHECK_FAILED (plans/harness's re-verification capability,
``services.finding_reverification``): evidence is append-only — a failed
recheck is never allowed to erase or edit a past REPRODUCTION/VERIFICATION/
ATTESTATION record, so the historical fact "this was confirmed once" is
never lost. What it changes is what the CURRENT confidence read means: if
the most recent recheck for this finding failed to reproduce it, CONFIRMED
would be actively misleading ("still true right now") even though it once
was. This is recency-aware, not a blanket downgrade — a later successful
re-verification (a fresh CONFIRMING record after the failed recheck) clears
it, the same way a flaky target coming back up should.
"""

from __future__ import annotations

from osprey.schemas.finding import EvidenceRecord, EvidenceRecordKind, FindingConfidence

# Evidence kinds strong enough to confirm a claim outright: an actual
# reproduction, a direct read of the config/permission in question, or a
# human saying so. None of these is type-specific — a reproduction record
# means the same thing whether it came from a SQLi PoC or a misconfigured
# S3 bucket check.
_CONFIRMING_KINDS = frozenset(
    {EvidenceRecordKind.REPRODUCTION, EvidenceRecordKind.VERIFICATION, EvidenceRecordKind.ATTESTATION}
)


def confidence_for(
    evidence_records: list[EvidenceRecord] | None,
    *,
    source_tools: list[str] | None = None,
) -> FindingConfidence:
    """Compute confidence from evidence alone.

    - a reproduction, a direct verification, or a human attestation → CONFIRMED
      — UNLESS the most recent RECHECK_FAILED is more recent than the most
      recent confirming record, in which case → LIKELY (it earned CONFIRMED
      once; the latest check couldn't reproduce it, so it's not honest to
      keep reporting it as currently confirmed).
    - >=2 independent source tools, or an explicit corroboration record → LIKELY
    - anything else (just the raw signal) → HYPOTHESIS
    """
    records = evidence_records or []
    tools: set[str] = {t.strip() for t in (source_tools or []) if t and t.strip()}
    kinds: set[EvidenceRecordKind] = set()
    latest_confirming_at = None
    latest_recheck_failed_at = None
    for er in records:
        kinds.add(er.kind)
        if er.source_tool and er.source_tool.strip():
            tools.add(er.source_tool.strip())
        if er.kind in _CONFIRMING_KINDS:
            if latest_confirming_at is None or er.created_at > latest_confirming_at:
                latest_confirming_at = er.created_at
        elif er.kind == EvidenceRecordKind.RECHECK_FAILED:
            if latest_recheck_failed_at is None or er.created_at > latest_recheck_failed_at:
                latest_recheck_failed_at = er.created_at

    if kinds & _CONFIRMING_KINDS:
        stale = (
            latest_recheck_failed_at is not None
            and (latest_confirming_at is None or latest_recheck_failed_at > latest_confirming_at)
        )
        if not stale:
            return FindingConfidence.CONFIRMED
        return FindingConfidence.LIKELY
    if len(tools) >= 2 or EvidenceRecordKind.CORROBORATION in kinds:
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
