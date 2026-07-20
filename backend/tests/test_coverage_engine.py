"""M2: soft coverage gaps + flexible finding fields."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.services.coverage_engine import compute_coverage_gaps
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.findings_store import get_findings_store


def test_flexible_finding_fields_persist() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "flex.test"}).json()

    store = get_findings_store()
    stored = store.add(
        Finding(
            engagement_id=eng["id"],
            run_id="r1",
            finding_type=FindingType.OBSERVATION,
            title="messy-tool-chunk",
            source_tool="custom",
            metadata={"nested_ok": True, "score": 0.9},
            tags=["unstructured", "manual"],
            extra={"rows": [{"a": 1}], "parser": None},
            raw_data="raw stdout fragment...\nline2",
            notes="saved because parser was incomplete",
        )
    )
    listed = store.list(engagement_id=eng["id"], limit=10)
    assert any(f.id == stored.id for f in listed)
    got = next(f for f in listed if f.id == stored.id)
    assert got.tags == ["unstructured", "manual"]
    assert got.extra["rows"] == [{"a": 1}]
    assert "raw stdout" in got.raw_data
    assert got.notes.startswith("saved because")


def test_sister_gaps_are_advisory_and_isolated() -> None:
    with TestClient(app) as client:
        a = client.post("/api/v1/engagements/", json={"target": "seed-a.com", "name": "a"}).json()
        b = client.post("/api/v1/engagements/", json={"target": "seed-b.com", "name": "b"}).json()

    store = get_findings_store()
    graph = get_engagement_graph()

    sister_a = Finding(
        engagement_id=a["id"],
        run_id="r",
        finding_type=FindingType.HOST,
        title="sister-a.com",
        source_tool="domain_hunter",
        tags=["sister_domain"],
        metadata={"role": "sister_domain"},
    )
    sister_b = Finding(
        engagement_id=b["id"],
        run_id="r",
        finding_type=FindingType.HOST,
        title="sister-b.com",
        source_tool="domain_hunter",
        tags=["sister_domain"],
        metadata={"role": "sister_domain"},
    )
    store.add_many([sister_a, sister_b])
    graph.ingest_many([sister_a, sister_b])

    gaps_a = compute_coverage_gaps(engagement_id=a["id"], phase="recon")
    gaps_b = compute_coverage_gaps(engagement_id=b["id"], phase="recon")

    assert all(g.advisory for g in gaps_a)
    assert any(g.gap_id == "sister_unenumerated" and g.asset == "sister-a.com" for g in gaps_a)
    assert not any(g.asset == "sister-b.com" for g in gaps_a)
    assert any(g.gap_id == "sister_unenumerated" and g.asset == "sister-b.com" for g in gaps_b)

    # Once a subdomain exists for the sister, drop the gap
    sub = Finding(
        engagement_id=a["id"],
        run_id="r",
        finding_type=FindingType.SUBDOMAIN,
        title="www.sister-a.com",
        source_tool="subfinder_scan",
    )
    store.add(sub)
    graph.ingest_finding(sub)
    gaps_a2 = compute_coverage_gaps(engagement_id=a["id"], phase="recon")
    assert not any(g.gap_id == "sister_unenumerated" and g.asset == "sister-a.com" for g in gaps_a2)


def test_coverage_api_requires_engagement() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "cov-api.test"}).json()
        ok = client.get(
            "/api/v1/hybrid/coverage/recon",
            params={"engagement_id": eng["id"]},
        )
        assert ok.status_code == 200
        assert isinstance(ok.json(), list)

        missing = client.get("/api/v1/hybrid/coverage/recon")
        assert missing.status_code == 422


def test_empty_engagement_id_returns_no_gaps() -> None:
    assert compute_coverage_gaps(engagement_id="", phase="full") == []
