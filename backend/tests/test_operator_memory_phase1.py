"""Phase 1: operator cognition write-back (graph_link, tag_asset, markers, think)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.services.crown_jewels import rank_crown_jewels
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.operator_memory import (
    is_hypothesis_relation,
    sanitize_relation,
    tag_asset,
)
from pentest_platform.services.parsers.freeform_probe import (
    extract_rel_markers,
    parse_freeform_probe_output,
)
from pentest_platform.services.summary_agent import summarize_execution
from pentest_platform.schemas.tools import ToolExecutionResponse


def test_sanitize_relation_hypothesis_prefix() -> None:
    assert sanitize_relation("same_app_as", evidence_grade="inferred") == "hypothesis_same_app_as"
    assert sanitize_relation("same_app_as", evidence_grade="observed") == "same_app_as"
    assert is_hypothesis_relation("hypothesis_same_app_as")
    assert not is_hypothesis_relation("hosted_on")


def test_graph_link_api_and_query() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "linkcorp.test", "name": "p1-link"},
        ).json()
        eid = eng["id"]
        resp = client.post(
            "/api/v1/hybrid/graph/link",
            json={
                "engagement_id": eid,
                "source": "host:erp.linkcorp.test",
                "target": "host:ess.linkcorp.test",
                "relation": "same_app_as",
                "evidence": "shared Angular chunk hash abc",
                "evidence_grade": "inferred",
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["hypothesis"] is True
        assert data["relationship"] == "hypothesis_same_app_as"
        assert data["finding_id"]

        q = client.get(
            "/api/v1/hybrid/graph/query",
            params={"engagement_id": eid, "contains": "erp"},
        ).json()
        assert q["count"] >= 1
        hyp_edges = [e for e in q["edges"] if e.get("hypothesis")]
        assert hyp_edges
        assert any(e["rel"] == "hypothesis_same_app_as" for e in hyp_edges)


def test_observed_link_no_hypothesis_prefix() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "obs-link.test"}).json()
        eid = eng["id"]
        data = client.post(
            "/api/v1/hybrid/graph/link",
            json={
                "engagement_id": eid,
                "source": "erp.obs-link.test",
                "target": "ess.obs-link.test",
                "relation": "shares_cookie_domain",
                "evidence": "Set-Cookie Domain=.obs-link.test on both",
                "evidence_grade": "observed",
            },
        ).json()
        assert data["hypothesis"] is False
        assert data["relationship"] == "shares_cookie_domain"
        edges = get_engagement_graph().list_edges(
            engagement_id=eid, relationship="shares_cookie_domain"
        )
        assert len(edges) >= 1


def test_tag_asset_boosts_crown_jewels() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "tagboost.test"}).json()
        eid = eng["id"]
        # Seed a bland host finding so asset appears
        from pentest_platform.schemas.finding import Finding, FindingType

        get_findings_store().add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.HOST,
                title="boring.tagboost.test",
                target="boring.tagboost.test",
                source_tool="test",
            )
        )
        before = {r["asset"]: r["score"] for r in rank_crown_jewels(eid, limit=20)}
        tag_asset(
            engagement_id=eid,
            asset="boring.tagboost.test",
            role="business_portal",
            boost=40,
            reason="operator marked PMIS-like",
        )
        after = {r["asset"]: r["score"] for r in rank_crown_jewels(eid, limit=20)}
        assert "boring.tagboost.test" in after
        assert after["boring.tagboost.test"] >= before.get("boring.tagboost.test", 0) + 40
        assert any(
            "tag:business_portal" in r["reasons"]
            for r in rank_crown_jewels(eid, limit=20)
            if r["asset"] == "boring.tagboost.test"
        )


def test_think_persists_finding() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "think.test"}).json()
        eid = eng["id"]
        data = client.post(
            "/api/v1/hybrid/think",
            json={
                "engagement_id": eid,
                "hypothesis": "erp and ess share auth",
                "plan": "compare cookies",
                "evidence": "same IP",
            },
        ).json()
        assert data["finding_id"]
        findings = get_findings_store().list(engagement_id=eid, limit=50)
        assert any("operator_think" in (f.tags or []) for f in findings)
        assert any("HYPOTHESIS:" in (f.title or "") for f in findings)


def test_rel_and_hypothesis_script_markers() -> None:
    stdout = """
HYPOTHESIS|shared farm|same TLS SAN
REL|inferred|host:a.marker.test|same_app_as|host:b.marker.test|chunk hash
FINDING|observed|info|host|a.marker.test|alive
"""
    markers = extract_rel_markers(stdout)
    assert len(markers) == 1
    assert markers[0]["relation"] == "same_app_as"

    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "marker.test"}).json()
        eid = eng["id"]

    findings = parse_freeform_probe_output(
        stdout, engagement_id=eid, run_id="r1", target="marker.test", source_tool="script:python3"
    )
    assert any("HYPOTHESIS:" in f.title for f in findings)

    resp = ToolExecutionResponse(
        success=True,
        tool_name="script:python3",
        command="python3",
        stdout=stdout,
        stderr="",
        returncode=0,
        timed_out=False,
    )
    summarize_execution(
        resp,
        engagement_id=eid,
        run_id="r1",
        target="marker.test",
        phase="recon",
        force_raw_observation=True,
    )
    edges = get_engagement_graph().list_edges(engagement_id=eid)
    assert any(e.relationship == "hypothesis_same_app_as" for e in edges)


def test_link_requires_evidence() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "noev.test"}).json()
        eid = eng["id"]
        bad = client.post(
            "/api/v1/hybrid/graph/link",
            json={
                "engagement_id": eid,
                "source": "a.noev.test",
                "target": "b.noev.test",
                "relation": "x",
                "evidence": "",
            },
        )
        assert bad.status_code == 400
