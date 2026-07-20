"""M5: per-IP ports_known vs services_known."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.services.coverage_engine import compute_coverage_gaps
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.network_surface import build_network_surface
from pentest_platform.services.tool_coverage_store import get_tool_coverage_store


def _seed_ip_engagement(target: str = "net-m5.test"):
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": target}).json()
    eid = eng["id"]
    store = get_findings_store()
    graph = get_engagement_graph()
    findings = [
        Finding(
            engagement_id=eid,
            finding_type=FindingType.SUBDOMAIN,
            title=f"www.{target}",
            metadata={"ip": "198.51.100.10"},
            source_tool="subfinder_scan",
        ),
        Finding(
            engagement_id=eid,
            finding_type=FindingType.SUBDOMAIN,
            title=f"api.{target}",
            metadata={"ip": "198.51.100.20"},
            source_tool="subfinder_scan",
        ),
    ]
    store.add_many(findings)
    graph.ingest_many(findings)
    return eid


def test_ip_unscanned_when_no_ports() -> None:
    eid = _seed_ip_engagement("unscan-m5.test")
    surface = build_network_surface(eid)
    assert surface is not None
    assert surface.unscanned_ips == 2
    assert all(not s.ports_known for s in surface.ips)

    gaps = compute_coverage_gaps(engagement_id=eid, phase="network")
    unscanned = [g for g in gaps if g.gap_id == "ip_unscanned"]
    assert len(unscanned) >= 2
    assert unscanned[0].suggested_tool == "nmap_syn_scan"
    assert "rustscan_fast_scan" in unscanned[0].alternatives
    assert unscanned[0].advisory is True


def test_ports_known_without_services() -> None:
    eid = _seed_ip_engagement("ports-m5.test")
    store = get_findings_store()
    graph = get_engagement_graph()
    port = Finding(
        engagement_id=eid,
        finding_type=FindingType.PORT,
        title="www.ports-m5.test:443",
        target="www.ports-m5.test",
        metadata={"port": 443},
        source_tool="nmap_syn_scan",
    )
    store.add(port)
    graph.ingest_finding(port)

    surface = build_network_surface(eid)
    assert surface is not None
    by_ip = {s.ip: s for s in surface.ips}
    assert by_ip["198.51.100.10"].ports_known is True
    assert by_ip["198.51.100.10"].services_known is False
    assert "443" in by_ip["198.51.100.10"].ports
    assert by_ip["198.51.100.20"].ports_known is False

    gaps = compute_coverage_gaps(engagement_id=eid, phase="network")
    no_svc = [g for g in gaps if g.gap_id == "ip_ports_no_service_scan"]
    assert any(g.asset == "198.51.100.10" for g in no_svc)
    g10 = next(g for g in no_svc if g.asset == "198.51.100.10")
    assert g10.suggested_tool == "nmap_service_scan"
    assert "443" in str(g10.suggested_params.get("ports", ""))

    # Dumb global pivot should not claim "subs but no ports" when some IPs have ports
    summary = get_engagement_graph().summary(engagement_id=eid)
    assert not any("Subdomains found but no port scan" in h for h in summary.pivot_hints)
    assert any("IP(s)" in h and "ports" in h.lower() for h in summary.pivot_hints)


def test_service_marks_services_known() -> None:
    eid = _seed_ip_engagement("svc-m5.test")
    store = get_findings_store()
    graph = get_engagement_graph()
    findings = [
        Finding(
            engagement_id=eid,
            finding_type=FindingType.PORT,
            title="www.svc-m5.test:22",
            target="www.svc-m5.test",
            metadata={"port": 22},
            source_tool="nmap_syn_scan",
        ),
        Finding(
            engagement_id=eid,
            finding_type=FindingType.SERVICE,
            title="ssh OpenSSH 8.9",
            target="www.svc-m5.test",
            metadata={"port": 22, "ip": "198.51.100.10"},
            source_tool="nmap_service_scan",
        ),
    ]
    store.add_many(findings)
    graph.ingest_many(findings)
    surface = build_network_surface(eid)
    assert surface is not None
    st = next(s for s in surface.ips if s.ip == "198.51.100.10")
    assert st.ports_known and st.services_known
    gaps = compute_coverage_gaps(engagement_id=eid, phase="network")
    assert not any(g.gap_id == "ip_ports_no_service_scan" and g.asset == "198.51.100.10" for g in gaps)


def test_network_surface_api_and_soft_coverage_lowers_confidence() -> None:
    eid = _seed_ip_engagement("api-m5.test")
    with TestClient(app) as client:
        resp = client.get(f"/api/v1/engagements/{eid}/network-surface")
        assert resp.status_code == 200
        body = resp.json()
        assert body["unscanned_ips"] == 2

    gaps1 = compute_coverage_gaps(engagement_id=eid, phase="network")
    conf1 = next(g.confidence for g in gaps1 if g.asset == "198.51.100.10")
    get_tool_coverage_store().record(
        engagement_id=eid,
        tool_name="nmap_syn_scan",
        asset="198.51.100.10",
        findings_count=0,
    )
    gaps2 = compute_coverage_gaps(engagement_id=eid, phase="network")
    conf2 = next(g.confidence for g in gaps2 if g.asset == "198.51.100.10")
    assert conf2 < conf1
