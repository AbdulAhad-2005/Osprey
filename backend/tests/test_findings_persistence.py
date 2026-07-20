"""M1: durable findings + graph with per-engagement isolation."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.run_store import get_run_store


def test_findings_isolated_by_engagement() -> None:
    with TestClient(app) as client:
        a = client.post("/api/v1/engagements/", json={"target": "alpha.example", "name": "alpha"}).json()
        b = client.post("/api/v1/engagements/", json={"target": "beta.example", "name": "beta"}).json()

    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=a["id"],
            run_id="run-a",
            finding_type=FindingType.SUBDOMAIN,
            title="www.alpha.example",
            source_tool="subfinder",
        )
    )
    store.add(
        Finding(
            engagement_id=b["id"],
            run_id="run-b",
            finding_type=FindingType.SUBDOMAIN,
            title="www.beta.example",
            source_tool="subfinder",
        )
    )
    # Same label on both engagements must not collide in the API filter
    store.add(
        Finding(
            engagement_id=a["id"],
            run_id="run-a",
            finding_type=FindingType.SUBDOMAIN,
            title="shared.label.example",
            source_tool="subfinder",
        )
    )
    store.add(
        Finding(
            engagement_id=b["id"],
            run_id="run-b",
            finding_type=FindingType.SUBDOMAIN,
            title="shared.label.example",
            source_tool="subfinder",
        )
    )

    alpha = store.list(engagement_id=a["id"], limit=100)
    beta = store.list(engagement_id=b["id"], limit=100)

    assert len(alpha) == 2
    assert len(beta) == 2
    assert all(f.engagement_id == a["id"] for f in alpha)
    assert all(f.engagement_id == b["id"] for f in beta)
    assert {f.title for f in alpha} == {"www.alpha.example", "shared.label.example"}
    assert {f.title for f in beta} == {"www.beta.example", "shared.label.example"}


def test_graph_nodes_isolated_by_engagement() -> None:
    with TestClient(app) as client:
        a = client.post("/api/v1/engagements/", json={"target": "graph-a.test"}).json()
        b = client.post("/api/v1/engagements/", json={"target": "graph-b.test"}).json()

    graph = get_engagement_graph()
    store = get_findings_store()

    finding_a = Finding(
        engagement_id=a["id"],
        run_id="ga",
        finding_type=FindingType.SUBDOMAIN,
        title="mail.shared.com",
        evidence="mail.shared.com resolves to 10.0.0.1",
        metadata={"ip": "10.0.0.1"},
        source_tool="dnsenum",
    )
    finding_b = Finding(
        engagement_id=b["id"],
        run_id="gb",
        finding_type=FindingType.SUBDOMAIN,
        title="mail.shared.com",
        evidence="mail.shared.com resolves to 10.0.0.2",
        metadata={"ip": "10.0.0.2"},
        source_tool="dnsenum",
    )
    store.add_many([finding_a, finding_b])
    graph.ingest_many([finding_a, finding_b])

    sum_a = graph.summary(engagement_id=a["id"])
    sum_b = graph.summary(engagement_id=b["id"])

    assert "mail.shared.com" in sum_a.subdomains
    assert "mail.shared.com" in sum_b.subdomains
    assert sum_a.node_count >= 2  # subdomain + ip
    assert sum_b.node_count >= 2
    # Different IPs must remain in their own engagement graphs
    sib_a = graph.siblings_same_ip("mail.shared.com", engagement_id=a["id"])
    assert sib_a.ip == "10.0.0.1"
    sib_b = graph.siblings_same_ip("mail.shared.com", engagement_id=b["id"])
    assert sib_b.ip == "10.0.0.2"


def test_findings_api_filters_by_engagement() -> None:
    with TestClient(app) as client:
        a = client.post("/api/v1/engagements/", json={"target": "api-a.test"}).json()
        b = client.post("/api/v1/engagements/", json={"target": "api-b.test"}).json()

        client.post(
            "/api/v1/findings/",
            json={
                "engagement_id": a["id"],
                "run_id": "r1",
                "finding_type": "host",
                "title": "only-a.host",
                "source_tool": "manual",
            },
        )
        client.post(
            "/api/v1/findings/",
            json={
                "engagement_id": b["id"],
                "run_id": "r2",
                "finding_type": "host",
                "title": "only-b.host",
                "source_tool": "manual",
            },
        )

        listed_a = client.get("/api/v1/findings/", params={"engagement_id": a["id"]}).json()
        listed_b = client.get("/api/v1/findings/", params={"engagement_id": b["id"]}).json()

        assert listed_a["total"] >= 1
        assert all(f["title"] != "only-b.host" for f in listed_a["findings"])
        assert listed_b["total"] >= 1
        assert all(f["title"] != "only-a.host" for f in listed_b["findings"])


def test_run_store_records_per_engagement() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "run-record.test"}).json()

    get_run_store().ensure(run_id="runabc123456", engagement_id=eng["id"])
    get_run_store().ensure(run_id="runabc123456", engagement_id=eng["id"])  # idempotent
