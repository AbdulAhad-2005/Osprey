"""Canonical report: one assembled structure, consistent across JSON + Markdown."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from osprey.main import app
from osprey.schemas.engagement import EngagementCreateRequest
from osprey.schemas.finding import Finding
from osprey.schemas.observation import Observation
from osprey.services.engagement_store import get_engagement_store
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store
from osprey.services.report_builder import build_report, render_markdown


def _seed() -> str:
    eng = get_engagement_store().create(EngagementCreateRequest(target="report.test"))
    get_observation_store().record_many([
        Observation(engagement_id=eng.id, type="subdomain", target="api.report.test", source_tool="subfinder"),
        Observation(engagement_id=eng.id, type="subdomain", target="app.report.test", source_tool="subfinder"),
        Observation(engagement_id=eng.id, type="host", target="app.report.test", source_tool="dnsx", details={"ip": "1.2.3.4"}),
        Observation(engagement_id=eng.id, type="technology", target="app.report.test", source_tool="httpx", details={"name": "nginx"}),
        Observation(engagement_id=eng.id, type="credential", target="report.test", source_tool="intelx",
                    details={"username": "admin@report.test", "password": "pw123"}),
    ])
    get_findings_store().add_many([
        Finding(engagement_id=eng.id, finding_type="vulnerability", title="RCE via upload",
                claim_severity="critical", confidence="confirmed", source_tool="manual", target="app.report.test",
                description="Arbitrary file upload leads to RCE.", evidence="uploaded shell.php; id -> uid=33"),
        Finding(engagement_id=eng.id, finding_type="vulnerability", title="Missing HSTS",
                claim_severity="low", confidence="confirmed", source_tool="httpx", target="app.report.test"),
    ])
    return eng.id


def test_build_report_structure_and_risk():
    eid = _seed()
    r = build_report(eid)
    assert r["meta"]["target"] == "report.test"
    # Highest finding is critical → overall risk Critical.
    assert r["executive_summary"]["overall_risk"] == "critical"
    ks = r["executive_summary"]["key_stats"]
    assert ks["subdomains"] == 2
    assert ks["technologies"] == 1
    assert ks["secrets"] == 1
    assert ks["findings"] == 2
    # Findings grouped, most-severe first.
    sevs = [g["severity"] for g in r["findings_by_severity"]]
    assert sevs[0] == "critical"
    # Methodology reflects real tools.
    phases = {p["phase"] for p in r["methodology"]}
    assert "Reconnaissance & Enumeration" in phases
    # Recon appendix carries the inventory.
    labels = {s["label"] for s in r["recon_appendix"]}
    assert "Subdomains" in labels and "Credentials & Secrets" in labels


def test_render_markdown_has_sections_and_remediation():
    eid = _seed()
    md = render_markdown(build_report(eid))
    for header in ["# Penetration Test Report", "## Executive Summary", "## Scope & Rules of Engagement",
                   "## Methodology", "## Findings", "## Appendix"]:
        assert header in md, f"missing section: {header}"
    assert "Remediation:" in md
    assert "RCE via upload" in md


def test_report_unknown_engagement_returns_error():
    r = build_report("no-such-engagement")
    assert "error" in r


def test_remediation_uses_recorded_advice_not_ambiguous_title_keywords():
    from osprey.services.report_generator import _build_findings_by_severity
    missing = Finding(finding_type="vulnerability", title="Full account takeover via password reset", claim_severity="critical")
    recorded = Finding(finding_type="vulnerability", title="Subdomain takeover", metadata={"remediation": "Remove the abandoned DNS record after confirming ownership."})
    rows = {f["title"]: f for group in _build_findings_by_severity([missing, recorded]) for f in group["findings"]}
    assert "has not been recorded" in rows[missing.title]["remediation_hint"]
    assert "CNAME" not in rows[missing.title]["remediation_hint"]
    assert rows[missing.title]["remediation_recorded"] is False
    assert rows[recorded.title]["remediation_hint"] == recorded.metadata["remediation"]
    assert rows[recorded.title]["remediation_recorded"] is True


def test_legacy_discoveries_are_inventory_not_security_findings():
    eid = _seed()
    get_findings_store().add_many([
        Finding(engagement_id=eid, finding_type="url", title="https://app.report.test/robots.txt", target="https://app.report.test/robots.txt", claim_severity="info"),
        Finding(engagement_id=eid, finding_type="observation", title="nmap failed: permission denied", claim_severity="none"),
    ])
    report = build_report(eid)
    assert report["totals"]["findings"] == 2
    assert report["supporting_records"]["count"] == 2
    assert any(item["value"] == "https://app.report.test/robots.txt" for section in report["recon_appendix"] for item in section["items"])
    markdown = render_markdown(report)
    assert "## Limitations & Validation Status" in markdown
    assert "## Remediation Priorities" in markdown


def test_inventory_splits_names_and_preserves_malformed_rows_for_review():
    eid = _seed()
    get_observation_store().record_many([
        Observation(engagement_id=eid, type="subdomain", target="report.test", details={"hostname":"one.report.test,two.report.test"}),
        Observation(engagement_id=eid, type="host", target="report.test", details={"hostname":"Host identified in a tool log"}),
    ])
    report = build_report(eid)
    subdomains = next(s for s in report["recon_appendix"] if s["key"] == "subdomains")
    assert {"one.report.test", "two.report.test"} <= {item["value"] for item in subdomains["items"]}
    review = next(s for s in report["recon_appendix"] if s["key"] == "review")
    assert any(item["value"] == "Host identified in a tool log" for item in review["items"])


def test_inventory_keeps_multiple_original_record_references():
    eid=_seed()
    get_observation_store().record_many([
        Observation(engagement_id=eid,type="technology",target="app.report.test",source_tool="other-scanner",details={"name":"nginx","version":"2"}),
    ])
    report=build_report(eid)
    section=next(s for s in report["recon_appendix"] if s["key"]=="technologies")
    nginx=next(item for item in section["items"] if item["value"]=="nginx")
    assert len([ref for ref in nginx["record_refs"] if ref["kind"]=="observation"])==2
    assert "other-scanner" in nginx["source_tool"]


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_report_endpoints(client):
    eid = _seed()
    rj = client.get(f"/api/v1/report/{eid}")
    assert rj.status_code == 200
    assert rj.json()["executive_summary"]["overall_risk"] == "critical"
    rm = client.get(f"/api/v1/report/{eid}/markdown")
    assert rm.status_code == 200
    assert "text/markdown" in rm.headers["content-type"]
    assert "# Penetration Test Report" in rm.text
