"""file_finding + promote_observations — plans/harness/03-earned-finding-
pipeline.md Steps 3+5. A Finding comes into existence exactly two ways here,
both computing confidence from evidence, never accepting it as input.
"""

from __future__ import annotations

import pytest

import pytest as _pytest

from osprey.schemas.finding import EvidenceRecord, EvidenceRecordKind, FindingConfidence, FindingType
from osprey.schemas.observation import Observation, ObservationType
from osprey.services import fp_cache, suppressed_promotion_store
from osprey.services.finding_pipeline import (
    FileFindingError,
    MarkFalsePositiveError,
    file_finding,
    mark_false_positive,
    promote_observations,
)
from osprey.services.observation_store import get_observation_store


@_pytest.fixture(autouse=True)
def _isolated_fp_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(fp_cache, "_FP_CACHE_DIR", tmp_path / "fp_cache")
    monkeypatch.setattr(fp_cache, "_PATTERNS_PATH", tmp_path / "fp_cache" / "patterns.jsonl")
    fp_cache.reload()
    yield
    fp_cache.reload()


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_file_finding_requires_at_least_one_observation_id():
    eid = _make_engagement("file-finding-empty.test")
    with pytest.raises(FileFindingError):
        file_finding(
            engagement_id=eid, title="X", finding_type=FindingType.VULNERABILITY,
            observation_ids=[],
        )


def test_file_finding_rejects_unknown_observation_ids():
    eid = _make_engagement("file-finding-unknown.test")
    with pytest.raises(FileFindingError):
        file_finding(
            engagement_id=eid, title="X", finding_type=FindingType.VULNERABILITY,
            observation_ids=["does-not-exist"],
        )


def test_file_finding_has_no_confidence_parameter():
    """Structural proof, not just a convention: the caller cannot pass a
    confidence — the function signature has no such parameter at all."""
    import inspect

    sig = inspect.signature(file_finding)
    assert "confidence" not in sig.parameters


def test_file_finding_with_no_evidence_records_yields_hypothesis():
    eid = _make_engagement("file-finding-hyp.test")
    obs = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="file-finding-hyp.test",
                    source_tool="nuclei_scan", details={"claimed_severity": "high"}),
    )
    result = file_finding(
        engagement_id=eid, title="Unconfirmed nuclei match", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id],
    )
    finding = result.finding
    assert finding is not None
    assert finding.confidence == FindingConfidence.HYPOTHESIS
    assert finding.observation_ids == [obs.id]
    assert finding.source_tools == ["nuclei_scan"]


def test_file_finding_with_reproduction_record_yields_confirmed():
    eid = _make_engagement("file-finding-confirmed.test")
    obs = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="file-finding-confirmed.test",
                    source_tool="sqlmap_scan", details={"claimed_severity": "critical"}),
    )
    result = file_finding(
        engagement_id=eid, title="SQLi reproduced", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id],
        evidence_records=[EvidenceRecord(kind=EvidenceRecordKind.REPRODUCTION, detail="dumped 5 rows")],
    )
    finding = result.finding
    assert finding is not None
    assert finding.confidence == FindingConfidence.CONFIRMED
    assert len(finding.evidence_records) == 1


def test_file_finding_claiming_confirmed_with_no_evidence_still_yields_hypothesis():
    """Say-so is not evidence — the caller's intent (a "confirmed"-sounding
    title/description) cannot move confidence; only evidence_records/
    source_tools can."""
    eid = _make_engagement("file-finding-sayso.test")
    obs = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="file-finding-sayso.test",
                    source_tool="nikto_scan"),
    )
    result = file_finding(
        engagement_id=eid, title="This is DEFINITELY confirmed and critical",
        finding_type=FindingType.VULNERABILITY, observation_ids=[obs.id],
    )
    assert result.finding is not None
    assert result.finding.confidence == FindingConfidence.HYPOTHESIS


def test_promote_observations_promotes_single_source_scanner_signal_as_hypothesis():
    eid = _make_engagement("promote-single.test")
    get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="promote-single.test",
                    source_tool="nuclei_scan", details={"title": "CVE-2099-0001 match", "claimed_severity": "high"}),
    )
    findings = promote_observations(eid)
    assert len(findings) == 1
    assert findings[0].confidence == FindingConfidence.HYPOTHESIS
    assert findings[0].claim_severity.value == "high"


def test_promote_observations_promotes_corroborated_signal_as_likely():
    eid = _make_engagement("promote-corroborated.test")
    store = get_observation_store()
    # Two independent tools reporting the exact same fact → merges into one
    # canonical observation with 2 distinct occurrence source_tools.
    store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="promote-corroborated.test",
        source_tool="nuclei_scan", details={"title": "CVE-2099-0002 match", "claimed_severity": "high"},
    ))
    store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="promote-corroborated.test",
        source_tool="jaeles_vulnerability_scan", details={"title": "CVE-2099-0002 match", "claimed_severity": "high"},
    ))
    findings = promote_observations(eid)
    assert len(findings) == 1
    assert findings[0].confidence == FindingConfidence.LIKELY
    assert set(findings[0].source_tools) == {"nuclei_scan", "jaeles_vulnerability_scan"}


def test_promote_observations_never_promotes_non_scanner_signal_types():
    """Widening promotion to other observation types (credentials, DNS
    posture, …) is explicitly out of scope for this pass — a PORT
    observation must never silently become a finding here."""
    eid = _make_engagement("promote-scoped.test")
    get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.PORT, target="promote-scoped.test",
                    source_tool="nmap_service_scan", details={"port": "443"}),
    )
    findings = promote_observations(eid)
    assert findings == []


def test_promote_observations_empty_engagement_returns_empty():
    eid = _make_engagement("promote-empty.test")
    assert promote_observations(eid) == []
    assert promote_observations("") == []


# --------------------------------------------------------------------------
# FP-cache — plans/harness/04-learning-fp-cache.md
# --------------------------------------------------------------------------

def test_file_finding_suppressed_by_matching_fp_pattern():
    eid = _make_engagement("fp-suppress.test")
    fp_cache.add_pattern(title_contains="known noise pattern", reason="always noise")
    obs = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="fp-suppress.test",
                    source_tool="nuclei_scan"),
    )
    result = file_finding(
        engagement_id=eid, title="This is a known noise pattern here",
        finding_type=FindingType.VULNERABILITY, observation_ids=[obs.id],
    )
    assert result.finding is None
    assert result.suppressed_reason == "always noise"

    audit = suppressed_promotion_store.list_for_engagement(eid)
    assert len(audit) == 1
    assert audit[0].reason == "always noise"


def test_promote_observations_suppresses_matching_pattern_but_keeps_others():
    eid = _make_engagement("fp-suppress-promote.test")
    fp_cache.add_pattern(title_contains="CVE-2099-9999")
    store = get_observation_store()
    store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="fp-suppress-promote.test",
        source_tool="nuclei_scan", details={"title": "CVE-2099-9999 match"},
    ))
    store.record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="fp-suppress-promote.test",
        source_tool="nikto_scan", details={"title": "CVE-2099-0000 match"},
    ))
    findings = promote_observations(eid)
    assert len(findings) == 1
    assert "CVE-2099-0000" in findings[0].title


def test_mark_false_positive_retracts_finding_and_prevents_recurrence():
    eid = _make_engagement("fp-mark.test")
    obs = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="fp-mark.test",
                    source_tool="nuclei_scan", details={"title": "Some noisy CVE match"}),
    )
    result = file_finding(
        engagement_id=eid, title="Some noisy CVE match", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id],
    )
    finding = result.finding
    assert finding is not None
    from osprey.services.findings_store import get_findings_store

    assert get_findings_store().get(finding.id) is not None

    mark_false_positive(finding.id, reason="confirmed FP after manual review")
    assert get_findings_store().get(finding.id) is None  # retracted

    # A second identical candidate on the same target is now suppressed.
    obs2 = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="fp-mark.test",
                    source_tool="jaeles_vulnerability_scan", details={"title": "Some noisy CVE match"}),
    )
    result2 = file_finding(
        engagement_id=eid, title="Some noisy CVE match", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs2.id],
    )
    assert result2.finding is None


def test_mark_false_positive_unknown_finding_raises():
    with pytest.raises(MarkFalsePositiveError):
        mark_false_positive("does-not-exist")


def test_mark_false_positive_default_scope_does_not_cross_targets():
    """Root-cause fix: marking noise on host A must never suppress the same
    -titled signal on host B unless the operator explicitly widens scope."""
    eid = _make_engagement("fp-cross-target.test")
    obs_a = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="host-a.test",
                    source_tool="nuclei_scan", details={"title": "nginx version disclosure"}),
    )
    result_a = file_finding(
        engagement_id=eid, title="nginx version disclosure", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs_a.id],
    )
    pattern = mark_false_positive(result_a.finding.id, reason="noise on host-a")
    assert pattern.target_glob == "host-a.test"

    obs_b = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="host-b.test",
                    source_tool="nuclei_scan", details={"title": "nginx version disclosure"}),
    )
    result_b = file_finding(
        engagement_id=eid, title="nginx version disclosure", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs_b.id],
    )
    assert result_b.finding is not None, "a different host's finding must not be suppressed by default"


def test_mark_false_positive_explicit_wildcard_still_widens_scope():
    eid = _make_engagement("fp-explicit-wildcard.test")
    obs_a = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="host-a.test",
                    source_tool="nuclei_scan", details={"title": "scanner self-banner noise"}),
    )
    result_a = file_finding(
        engagement_id=eid, title="scanner self-banner noise", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs_a.id],
    )
    pattern = mark_false_positive(result_a.finding.id, reason="always noise", target_glob="*")
    assert pattern.target_glob == "*"

    obs_b = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="host-b.test",
                    source_tool="nuclei_scan", details={"title": "scanner self-banner noise"}),
    )
    result_b = file_finding(
        engagement_id=eid, title="scanner self-banner noise", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs_b.id],
    )
    assert result_b.finding is None, "an explicit wildcard scope must still widen as before"


def test_removing_pattern_re_enables_promotion():
    eid = _make_engagement("fp-unsuppress.test")
    pattern = fp_cache.add_pattern(title_contains="temporarily noisy")
    obs = get_observation_store().record(
        Observation(engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="fp-unsuppress.test",
                    source_tool="nuclei_scan"),
    )
    suppressed = file_finding(
        engagement_id=eid, title="temporarily noisy signal", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id],
    )
    assert suppressed.finding is None

    fp_cache.remove_pattern(pattern.id)
    allowed = file_finding(
        engagement_id=eid, title="temporarily noisy signal", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id],
    )
    assert allowed.finding is not None
