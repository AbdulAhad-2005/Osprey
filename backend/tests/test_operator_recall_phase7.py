"""Phase 7: queryable memory — flashlight for elite operators."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import EvidenceGrade, Finding, FindingType
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.operator_memory import link_assets
from pentest_platform.services.operator_recall import (
    attempts_for_asset,
    evidence_chain,
    memory_search,
)
from pentest_platform.services.tool_coverage_store import get_tool_coverage_store


def test_memory_search_finds_finding_and_attempt() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "recall-p7.test", "name": "p7"},
        ).json()
    eid = eng["id"]
    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=eid,
            finding_type=FindingType.OBSERVATION,
            title="Set-Cookie Domain=.recall-p7.test on portal",
            evidence="Set-Cookie: SID=1; Domain=.recall-p7.test",
            evidence_grade=EvidenceGrade.OBSERVED,
            source_tool="httpx_probe",
            target="portal.recall-p7.test",
            tags=["cookie"],
        )
    )
    get_tool_coverage_store().record(
        engagement_id=eid,
        tool_name="httpx_probe",
        asset="portal.recall-p7.test",
        findings_count=1,
        success=True,
    )
    packet = memory_search(eid, "cookie")
    assert packet["count"] >= 1
    assert any("cookie" in (h.get("title") or "").lower() for h in packet["hits"])
    # attempts may attach via related asset from hit titles
    near = attempts_for_asset(eid, asset="portal.recall-p7.test")
    assert near["count"] >= 1

    api = client.get(
        "/api/v1/hybrid/memory-search",
        params={"engagement_id": eid, "q": "portal"},
    ).json()
    assert api["count"] >= 1


def test_evidence_chain_walk() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "chain-p7.test"},
        ).json()
    eid = eng["id"]
    parent = get_findings_store().add(
        Finding(
            engagement_id=eid,
            finding_type=FindingType.OBSERVATION,
            title="HTTP title Shared Portal",
            evidence="title Shared Portal " + ("x" * 40),
            evidence_grade=EvidenceGrade.OBSERVED,
            source_tool="httpx_probe",
        )
    )
    link = link_assets(
        engagement_id=eid,
        source="host:a.chain-p7.test",
        target="host:b.chain-p7.test",
        relation="likely_same_app",
        evidence="similar titles",
        evidence_grade="inferred",
        derived_from=[parent.id],
    )
    chain = evidence_chain(eid, link["finding_id"])
    assert chain["ok"] is True
    assert any(p["id"] == parent.id for p in chain["parents"])


def test_attempts_are_advisory_not_ban() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "try-p7.test"},
        ).json()
    eid = eng["id"]
    get_tool_coverage_store().record(
        engagement_id=eid,
        tool_name="amass_scan",
        asset="try-p7.test",
        success=False,
        notes="timeout",
    )
    packet = attempts_for_asset(eid, asset="try-p7.test")
    assert packet["count"] >= 1
    assert "ban" not in packet["note"].lower()
    note = (packet.get("note") or "").lower()
    assert "re-run" in note or "useful" in note or "history" in note
