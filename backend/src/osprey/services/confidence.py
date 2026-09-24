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
    - >=2 independent source tools, or an explicit corroboration record → LIKELY
    - anything else (just the raw signal) → HYPOTHESIS
    """
    records = evidence_records or []
    tools: set[str] = {t.strip() for t in (source_tools or []) if t and t.strip()}
    kinds: set[EvidenceRecordKind] = set()
    for er in records:
        kinds.add(er.kind)
        if er.source_tool and er.source_tool.strip():
            tools.add(er.source_tool.strip())

    if kinds & _CONFIRMING_KINDS:
        return FindingConfidence.CONFIRMED
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
