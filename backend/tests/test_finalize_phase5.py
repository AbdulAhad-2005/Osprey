"""Phase 5: evidence chains, finalize v2, report outline, trim."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import (
    ClaimSeverity,
    EvidenceGrade,
    Finding,
    FindingType,
)
from pentest_platform.services.evidence_chain import normalize_derived_from
from pentest_platform.services.finalize_readiness import compute_finalize_readiness
from pentest_platform.services.finalize_rules import reload_finalize_rules
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.operator_memory import link_assets
from pentest_platform.services.report_outline import build_report_outline


def test_derived_from_on_graph_link() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "chain-p5.test", "name": "p5-chain"},
        ).json()
    eid = eng["id"]
    parent = get_findings_store().add(
        Finding(
            engagement_id=eid,
            finding_type=FindingType.OBSERVATION,
            title="HTTP title Acme Portal",
            evidence="Server: nginx title Acme Portal " + ("x" * 40),
            evidence_grade=EvidenceGrade.OBSERVED,
            source_tool="httpx_probe",
            target="a.chain-p5.test",
        )
    )
    result = link_assets(
        engagement_id=eid,
        source="host:a.chain-p5.test",
        target="host:b.chain-p5.test",
        relation="likely_same_app",
        evidence="similar titles on co-hosted names",
        evidence_grade="inferred",
        derived_from=[parent.id],
    )
    assert result["hypothesis"] is True
    assert parent.id in (result.get("derived_from") or [])
    assert "abc123def456" in normalize_derived_from("abc123def456, not-an-id!")


def test_hypothesis_path_soft_by_default_hard_when_enabled() -> None:
    reload_finalize_rules()
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "hyp-p5.test", "name": "p5-hyp"},
        ).json()
    eid = eng["id"]
    store = get_findings_store()
    for i in range(6):
        store.add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.URL,
                title=f"https://h{i}.hyp-p5.test/",
                evidence="HTTP/1.1 200 OK Server: nginx " + ("body " * 20),
                evidence_grade=EvidenceGrade.OBSERVED,
                claim_severity=ClaimSeverity.INFO,
                source_tool="httpx_probe",
            )
        )
    link_assets(
        engagement_id=eid,
        source="host:erp.hyp-p5.test",
        target="host:ess.hyp-p5.test",
        relation="shares_auth",
        evidence="same cookie domain hypothesis",
        evidence_grade="inferred",
    )
    # Default config: soft warning, not a hard COMPLETE trap
    ready = compute_finalize_readiness(engagement_id=eid)
    assert "hypothesis_only_attack_path" not in (ready.get("blocked_by") or [])
    warn = " ".join(ready.get("soft_warnings") or []).lower()
    assert "hypothesis" in warn or ready["checks"].get("hypothesis_attack_paths")

    # Optional hard gate stays available via config (patch the symbol finalize uses)
    from pentest_platform.services import finalize_readiness as fin_mod

    original = fin_mod.load_finalize_rules

    def _hard() -> dict:
        data = dict(original())
        data["block_hypothesis_only_paths"] = True
        return data

    fin_mod.load_finalize_rules = _hard  # type: ignore[assignment]
    try:
        hard = compute_finalize_readiness(engagement_id=eid)
        assert "hypothesis_only_attack_path" in (hard.get("blocked_by") or [])
    finally:
        fin_mod.load_finalize_rules = original  # type: ignore[assignment]
        reload_finalize_rules()


def test_report_outline_sections() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "outline-p5.test"},
        ).json()
        eid = eng["id"]
        store = get_findings_store()
        store.add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.OBSERVATION,
                title="Observed banner SSH-2.0-OpenSSH",
                evidence="SSH-2.0-OpenSSH_8.9 " + ("x" * 40),
                evidence_grade=EvidenceGrade.OBSERVED,
                source_tool="nmap_service_scan",
            )
        )
        store.add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.SUBDOMAIN,
                title="dns.outline-p5.test",
                evidence="from CT",
                evidence_grade=EvidenceGrade.INFERRED,
                source_tool="subfinder_scan",
            )
        )
        outline = client.get(
            "/api/v1/hybrid/report-outline",
            params={"engagement_id": eid},
        ).json()
        assert outline["counts"]["observed"] >= 1
        assert outline["counts"]["inferred"] >= 1
        text = outline["text"].lower()
        assert "observed" in text
        assert "inferred" in text
        assert "hypothes" in text
        packet = build_report_outline(eid)
        assert "Anti-hype" in packet["text"] or "anti-hype" in packet["text"].lower()
