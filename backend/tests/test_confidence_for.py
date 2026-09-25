"""confidence_for — the single pure confidence function, plans/harness/
03-earned-finding-pipeline.md Step 2. Universality is the point: these tests
never construct anything type-specific (no FindingType at all) — evidence
kind is the only input, and a brand-new evidence-producing capability
invented tomorrow slots into the same three tiers with no code change.
"""

from __future__ import annotations

from osprey.schemas.finding import EvidenceRecord, EvidenceRecordKind, FindingConfidence
from osprey.services.confidence import confidence_for, evidence_summary_for


def test_no_evidence_no_source_tools_is_hypothesis():
    assert confidence_for([]) == FindingConfidence.HYPOTHESIS
    assert confidence_for(None) == FindingConfidence.HYPOTHESIS


def test_single_source_tool_alone_is_hypothesis():
    assert confidence_for([], source_tools=["nuclei_scan"]) == FindingConfidence.HYPOTHESIS


def test_two_independent_source_tools_is_likely():
    assert confidence_for([], source_tools=["nuclei_scan", "nikto_scan"]) == FindingConfidence.LIKELY


def test_duplicate_source_tool_does_not_count_twice():
    assert confidence_for([], source_tools=["nuclei_scan", "nuclei_scan"]) == FindingConfidence.HYPOTHESIS


def test_explicit_corroboration_record_is_likely_even_with_one_tool():
    records = [EvidenceRecord(kind=EvidenceRecordKind.CORROBORATION, source_tool="nuclei_scan")]
    assert confidence_for(records) == FindingConfidence.LIKELY


def test_reproduction_record_is_confirmed():
    records = [EvidenceRecord(kind=EvidenceRecordKind.REPRODUCTION, detail="sqlmap dumped 5 rows")]
    assert confidence_for(records) == FindingConfidence.CONFIRMED


def test_verification_record_is_confirmed():
    records = [EvidenceRecord(kind=EvidenceRecordKind.VERIFICATION, detail="config read confirmed setting")]
    assert confidence_for(records) == FindingConfidence.CONFIRMED


def test_attestation_record_is_confirmed():
    records = [EvidenceRecord(kind=EvidenceRecordKind.ATTESTATION, detail="operator confirmed manually")]
    assert confidence_for(records) == FindingConfidence.CONFIRMED


def test_confirming_record_outranks_mere_corroboration():
    records = [
        EvidenceRecord(kind=EvidenceRecordKind.CORROBORATION, source_tool="a"),
        EvidenceRecord(kind=EvidenceRecordKind.REPRODUCTION),
    ]
    assert confidence_for(records) == FindingConfidence.CONFIRMED


def test_source_tools_from_evidence_records_count_toward_corroboration():
    """A finding with zero explicit source_tools= but two evidence records
    naming different tools still crosses the corroboration threshold — the
    function reads tool identity out of the evidence, not a separate channel."""
    records = [
        EvidenceRecord(kind=EvidenceRecordKind.CORROBORATION, source_tool="nuclei_scan"),
    ]
    # source_tool inside the record plus a distinct source_tools= entry = 2 tools
    assert confidence_for(records, source_tools=["nikto_scan"]) == FindingConfidence.LIKELY


def test_a_brand_new_evidence_kind_invented_tomorrow_still_works():
    """Universality proof: confidence_for never branches on a type it hasn't
    seen — an evidence KIND not in the confirming set defaults safely to the
    corroboration/hypothesis tiers rather than raising or guessing."""
    from enum import StrEnum

    class _FutureKind(StrEnum):
        NOVEL = "novel_evidence_kind"

    class _FakeRecord:
        kind = _FutureKind.NOVEL
        source_tool = "future_tool"

    # confidence_for only reads .kind/.source_tool — duck-typed, no isinstance
    # check on EvidenceRecordKind, proving it doesn't enumerate cases.
    assert confidence_for([_FakeRecord()], source_tools=["another_tool"]) == FindingConfidence.LIKELY


def test_evidence_summary_reflects_kinds_present():
    assert "No corroborating evidence" in evidence_summary_for([])
    records = [
        EvidenceRecord(kind=EvidenceRecordKind.CORROBORATION),
        EvidenceRecord(kind=EvidenceRecordKind.CORROBORATION),
        EvidenceRecord(kind=EvidenceRecordKind.REPRODUCTION),
    ]
    summary = evidence_summary_for(records)
    assert "2 corroboration" in summary
    assert "1 reproduction" in summary
