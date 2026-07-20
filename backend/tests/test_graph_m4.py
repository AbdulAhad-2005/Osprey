"""M4: sister lineage, co_hosts, CF flags, soft tool coverage."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.services.coverage_engine import compute_coverage_gaps
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.parsers.recon_network import parse_httpx
from pentest_platform.services.tool_coverage_store import get_tool_coverage_store


def test_sister_affiliated_with_edge() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "seedcorp.com", "name": "m4-sister"},
        ).json()
    eid = eng["id"]
    f = Finding(
        engagement_id=eid,
        run_id="m4",
        finding_type=FindingType.HOST,
        title="vpn.sistercorp.com",
        source_tool="domain_hunter",
        target="seedcorp.com",
        tags=["sister_domain"],
        metadata={"role": "sister_domain"},
    )
    get_findings_store().add(f)
    get_engagement_graph().ingest_finding(f)
    edges = get_engagement_graph().list_edges(engagement_id=eid, relationship="affiliated_with")
    assert len(edges) >= 1
    assert edges[0].source_id.startswith("domain:")
    assert "vpn.sistercorp.com" in edges[0].target_id


def test_co_hosts_edge_on_shared_ip() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "shared-ip.test"}).json()
    eid = eng["id"]
    a = Finding(
        engagement_id=eid,
        finding_type=FindingType.SUBDOMAIN,
        title="a.shared-ip.test",
        metadata={"ip": "203.0.113.10"},
        source_tool="dnsenum_scan",
    )
    b = Finding(
        engagement_id=eid,
        finding_type=FindingType.SUBDOMAIN,
        title="b.shared-ip.test",
        metadata={"ip": "203.0.113.10"},
        source_tool="dnsenum_scan",
    )
    store = get_findings_store()
    graph = get_engagement_graph()
    store.add_many([a, b])
    graph.ingest_many([a, b])
    co = graph.list_edges(engagement_id=eid, relationship="co_hosts")
    assert len(co) >= 2  # bidirectional
    summary = graph.summary(engagement_id=eid)
    assert any("Shared infra" in h or "co_hosts" in h for h in summary.pivot_hints)


def test_httpx_cloudflare_detection() -> None:
    stdout = "https://cf.example.com [cloudflare] 200 CF-Ray: abc123"
    findings = parse_httpx(stdout, engagement_id="x", run_id="y")
    urls = [f for f in findings if f.finding_type == FindingType.URL]
    assert urls
    assert urls[0].metadata.get("is_cloudflare") is True
    assert "cloudflare" in urls[0].tags


def test_tool_coverage_soft_mark_and_lowers_gap_confidence() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "covmark.test"}).json()
    eid = eng["id"]
    sister = Finding(
        engagement_id=eid,
        finding_type=FindingType.HOST,
        title="pending.sister.test",
        source_tool="domain_hunter",
        target="covmark.test",
        tags=["sister_domain"],
        metadata={"role": "sister_domain"},
    )
    get_findings_store().add(sister)
    get_engagement_graph().ingest_finding(sister)

    gaps_before = compute_coverage_gaps(engagement_id=eid, phase="recon")
    sister_gaps = [g for g in gaps_before if g.gap_id == "sister_unenumerated"]
    assert sister_gaps
    conf_before = sister_gaps[0].confidence

    get_tool_coverage_store().record(
        engagement_id=eid,
        tool_name="subfinder_scan",
        asset="pending.sister.test",
        findings_count=0,
        notes="already ran",
    )
    gaps_after = compute_coverage_gaps(engagement_id=eid, phase="recon")
    sister_after = next(g for g in gaps_after if g.asset == "pending.sister.test")
    assert sister_after.confidence <= conf_before
    assert sister_after.confidence <= 0.35
    assert sister_after.advisory is True

    with TestClient(app) as client:
        resp = client.get(f"/api/v1/engagements/{eid}/tool-coverage")
        assert resp.status_code == 200
        assert any(r["tool_name"] == "subfinder_scan" for r in resp.json())
