"""finding_reverification.reverify_finding + findings_store.append_evidence —
the re-verification gap closed this session (adapted, not copied, from
Pentest-Swarm-AI's ConfirmationAgent concept found during the alternatives
survey): re-run the tool(s) behind a finding's evidence and check whether the
signal still reproduces. Evidence stays append-only throughout — a failed
recheck is never allowed to edit or delete a past confirming record.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from osprey.schemas.finding import ClaimSeverity, EvidenceRecord, EvidenceRecordKind, FindingType, RecheckReason
from osprey.schemas.observation import Observation, ObservationType
from osprey.services import finding_reverification
from osprey.services.finding_pipeline import file_finding
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def _record_scanner_signal(eid: str, *, target: str, title: str, tool: str = "nuclei_scan") -> Observation:
    return get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target=target,
        source_tool=tool, details={"title": title, "claimed_severity": "critical"},
    ))


def test_append_evidence_recomputes_confidence_and_can_downgrade():
    from osprey.services.finding_pipeline import confirm_finding

    eid = _make_engagement("reverify-append.test")
    obs = _record_scanner_signal(eid, target="a.reverify-append.test", title="RCE via deserialization")
    result = file_finding(
        engagement_id=eid, title="RCE via deserialization", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id], claim_severity=ClaimSeverity.CRITICAL,
    )
    finding = result.finding
    assert finding is not None
    # Operator confirmation (the only path to CONFIRMED without a grounded artifact).
    assert confirm_finding(finding.id).confidence.value == "confirmed"

    store = get_findings_store()
    updated = store.append_evidence(finding.id, EvidenceRecord(
        kind=EvidenceRecordKind.RECHECK_FAILED, source_tool="nuclei_scan", observation_id=obs.id,
        reason=RecheckReason.NOT_REPRODUCED.value, detail="did not reproduce",
    ))
    assert updated is not None
    assert updated.confidence.value == "likely"
    kinds = {er.kind.value for er in updated.evidence_records}
    # Past evidence is untouched, not replaced — both records coexist.
    assert kinds == {"attestation", "recheck_failed"}


def test_append_evidence_unknown_finding_returns_none():
    store = get_findings_store()
    assert store.append_evidence("does-not-exist-12", EvidenceRecord(kind=EvidenceRecordKind.RECHECK_FAILED)) is None


def test_reverify_unknown_finding_reports_error():
    result = asyncio.run(finding_reverification.reverify_finding("does-not-exist-12"))
    assert "error" in result


def test_reverify_finding_with_no_reverifiable_observation_reports_nothing_to_check():
    """An ATTESTATION-only finding with an operator_record-sourced
    observation has nothing mechanical to re-run — reports that plainly
    instead of guessing or crashing."""
    eid = _make_engagement("reverify-none.test")
    obs = get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.RAW, target="a.reverify-none.test",
        source_tool="operator_record", details={"title": "manual note"},
    ))
    result = file_finding(
        engagement_id=eid, title="manual vuln note", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id],
        evidence_records=[EvidenceRecord(kind=EvidenceRecordKind.ATTESTATION, detail="I saw this")],
    )
    finding = result.finding
    assert finding is not None

    outcome = asyncio.run(finding_reverification.reverify_finding(finding.id))
    assert outcome["checked"] == 0
    assert "Nothing re-runnable" in outcome["note"]


def test_reverify_finding_downgrades_when_signal_no_longer_reproduces():
    """The tool re-runs cleanly (success) but the observation store never sees
    the same signature again — exactly what "the target no longer exhibits this"
    looks like. Confidence must move CONFIRMED -> LIKELY with a NOT_REPRODUCED
    recheck record."""
    eid = _make_engagement("reverify-fail.test")
    real_output = "sqlmap identified the following injection point: id=1 AND SLEEP(5) -- dumped 5 rows"
    obs = get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="b.reverify-fail.test",
        source_tool="sqlmap_scan", details={"title": "SQL injection", "claimed_severity": "critical", "snippet": real_output},
    ))
    result = file_finding(
        engagement_id=eid, title="SQL injection", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id], claim_severity=ClaimSeverity.CRITICAL,
        evidence_records=[EvidenceRecord(kind=EvidenceRecordKind.REPRODUCTION, detail=real_output)],
    )
    finding = result.finding
    assert finding is not None
    assert finding.confidence.value == "confirmed"

    with patch(
        "osprey.services.tool_execution.execute_tool_request",
        new=AsyncMock(return_value=SimpleNamespace(success=True)),  # ran clean, no re-observation
    ):
        outcome = asyncio.run(finding_reverification.reverify_finding(finding.id))

    assert outcome["checked"] == 1
    assert outcome["failed"] == 1
    assert outcome["reproduced"] == 0
    assert outcome["confidence_before"] == "confirmed"
    assert outcome["confidence_after"] == "likely"

    refiled = get_findings_store().get(finding.id)
    recheck = [er for er in refiled.evidence_records if er.kind == EvidenceRecordKind.RECHECK_FAILED]
    assert recheck and recheck[-1].reason == RecheckReason.NOT_REPRODUCED.value
    # The original REPRODUCTION record is still there — never deleted.
    assert any(er.kind == EvidenceRecordKind.REPRODUCTION for er in refiled.evidence_records)


def test_reverify_finding_stays_confirmed_when_signal_still_reproduces():
    """The mocked tool call re-records the SAME observation via record_many
    — observation_store bumps last_seen_at on a matching signature, which is
    exactly the "still true right now" signal reverify_finding looks for."""
    eid = _make_engagement("reverify-ok.test")
    real_output = "Reflected payload executed: <script>alert(document.domain)</script> rendered unescaped"
    obs = get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="c.reverify-ok.test",
        source_tool="nuclei_scan", details={"title": "XSS reflected", "claimed_severity": "high", "snippet": real_output},
    ))
    result = file_finding(
        engagement_id=eid, title="XSS reflected", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id], claim_severity=ClaimSeverity.HIGH,
        evidence_records=[EvidenceRecord(kind=EvidenceRecordKind.REPRODUCTION, detail=real_output)],
    )
    finding = result.finding
    assert finding is not None

    async def _fake_execute(*_args, **_kwargs):
        # Simulate the tool re-observing the exact same fact — the real path
        # goes through the parser -> observation_store.record_many, which is
        # what actually bumps last_seen_at on a signature match. Must match
        # the original observation's details exactly (signature = type +
        # target + normalized-details, schemas/observation.py) or this reads
        # as a DIFFERENT fact rather than a re-observation of the same one.
        get_observation_store().record(Observation(
            engagement_id=eid, type=ObservationType.SCANNER_SIGNAL, target="c.reverify-ok.test",
            source_tool="nuclei_scan", details={"title": "XSS reflected", "claimed_severity": "high", "snippet": real_output},
        ))
        return SimpleNamespace(success=True)

    with patch("osprey.services.tool_execution.execute_tool_request", new=_fake_execute):
        outcome = asyncio.run(finding_reverification.reverify_finding(finding.id))

    assert outcome["checked"] == 1
    assert outcome["reproduced"] == 1
    assert outcome["failed"] == 0
    assert outcome["confidence_after"] == "confirmed"

    refiled = get_findings_store().get(finding.id)
    assert not any(er.kind == EvidenceRecordKind.RECHECK_FAILED for er in refiled.evidence_records)


def test_reverify_finding_treats_a_tool_exception_as_inconclusive():
    """A tool that can't run learns nothing about the target (B4), so it must
    NOT downgrade a past confirmation — it records an INCONCLUSIVE recheck and
    leaves confidence unchanged."""
    from osprey.services.finding_pipeline import confirm_finding

    eid = _make_engagement("reverify-error.test")
    obs = _record_scanner_signal(eid, target="d.reverify-error.test", title="open redirect")
    result = file_finding(
        engagement_id=eid, title="open redirect", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id],
    )
    finding = result.finding
    assert finding is not None
    assert confirm_finding(finding.id).confidence.value == "confirmed"

    async def _boom(*_a, **_kw):
        raise RuntimeError("tool crashed")

    with patch("osprey.services.tool_execution.execute_tool_request", new=_boom):
        outcome = asyncio.run(finding_reverification.reverify_finding(finding.id))

    assert outcome["failed"] == 1
    assert outcome["confidence_after"] == "confirmed"  # unchanged — inconclusive
    refiled = get_findings_store().get(finding.id)
    recheck = [er for er in refiled.evidence_records if er.kind == EvidenceRecordKind.RECHECK_FAILED]
    assert recheck and recheck[-1].reason == RecheckReason.INCONCLUSIVE.value


def test_reverify_finding_treats_a_soft_tool_failure_as_inconclusive():
    """The tool ran but did not complete cleanly (success=False, e.g. target
    unreachable) — also inconclusive, no downgrade."""
    from osprey.services.finding_pipeline import confirm_finding

    eid = _make_engagement("reverify-soft.test")
    obs = _record_scanner_signal(eid, target="e.reverify-soft.test", title="SSRF")
    result = file_finding(
        engagement_id=eid, title="SSRF", finding_type=FindingType.VULNERABILITY,
        observation_ids=[obs.id],
    )
    finding = result.finding
    assert finding is not None
    assert confirm_finding(finding.id).confidence.value == "confirmed"

    with patch(
        "osprey.services.tool_execution.execute_tool_request",
        new=AsyncMock(return_value=SimpleNamespace(success=False)),
    ):
        outcome = asyncio.run(finding_reverification.reverify_finding(finding.id))

    assert outcome["failed"] == 1
    assert outcome["confidence_after"] == "confirmed"
    refiled = get_findings_store().get(finding.id)
    recheck = [er for er in refiled.evidence_records if er.kind == EvidenceRecordKind.RECHECK_FAILED]
    assert recheck and recheck[-1].reason == RecheckReason.INCONCLUSIVE.value
