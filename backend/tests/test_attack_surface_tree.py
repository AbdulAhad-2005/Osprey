"""M3: attack-surface tree export (per engagement)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.services.attack_surface_tree import build_attack_surface_tree
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.findings_store import get_findings_store


def test_tree_groups_seed_sisters_and_orphans() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "seed.example", "name": "tree-test"},
        ).json()
        eid = eng["id"]

    store = get_findings_store()
    graph = get_engagement_graph()
    findings = [
        Finding(
            engagement_id=eid,
            run_id="t1",
            finding_type=FindingType.HOST,
            title="sister.example",
            source_tool="domain_hunter",
            tags=["sister_domain"],
            metadata={"role": "sister_domain"},
        ),
        Finding(
            engagement_id=eid,
            run_id="t1",
            finding_type=FindingType.SUBDOMAIN,
            title="www.seed.example",
            source_tool="subfinder_scan",
            metadata={"ip": "10.0.0.1"},
        ),
        Finding(
            engagement_id=eid,
            run_id="t1",
            finding_type=FindingType.SUBDOMAIN,
            title="mail.sister.example",
            source_tool="subfinder_scan",
            metadata={"ip": "10.0.0.2"},
        ),
        Finding(
            engagement_id=eid,
            run_id="t1",
            finding_type=FindingType.HOST,
            title="lonely.orphan.net",
            source_tool="manual",
        ),
        Finding(
            engagement_id=eid,
            run_id="t1",
            finding_type=FindingType.PORT,
            title="www.seed.example:443",
            target="www.seed.example",
            metadata={"port": 443},
            source_tool="nmap_syn_scan",
        ),
    ]
    store.add_many(findings)
    graph.ingest_many(findings)

    tree = build_attack_surface_tree(eid)
    assert tree is not None
    assert tree.seed == "seed.example"
    assert tree.seed_branch is not None
    assert any(h.host == "www.seed.example" for h in tree.seed_branch.subdomains)
    assert any(s.domain == "sister.example" for s in tree.sisters)
    sister = next(s for s in tree.sisters if s.domain == "sister.example")
    assert any(h.host == "mail.sister.example" for h in sister.subdomains)
    assert any(h.host == "lonely.orphan.net" for h in tree.orphans)
    assert tree.stats.sisters >= 1
    assert tree.advisory is True

    with TestClient(app) as client:
        resp = client.get(f"/api/v1/engagements/{eid}/tree")
        assert resp.status_code == 200
        body = resp.json()
        assert body["seed"] == "seed.example"
        assert body["stats"]["sisters"] >= 1


def test_trees_do_not_cross_engagements() -> None:
    with TestClient(app) as client:
        a = client.post("/api/v1/engagements/", json={"target": "alpha.com"}).json()
        b = client.post("/api/v1/engagements/", json={"target": "beta.com"}).json()

    store = get_findings_store()
    graph = get_engagement_graph()
    fa = Finding(
        engagement_id=a["id"],
        finding_type=FindingType.SUBDOMAIN,
        title="www.alpha.com",
        source_tool="subfinder_scan",
    )
    fb = Finding(
        engagement_id=b["id"],
        finding_type=FindingType.SUBDOMAIN,
        title="www.beta.com",
        source_tool="subfinder_scan",
    )
    store.add_many([fa, fb])
    graph.ingest_many([fa, fb])

    ta = build_attack_surface_tree(a["id"])
    tb = build_attack_surface_tree(b["id"])
    assert ta is not None and tb is not None
    assert any(h.host == "www.alpha.com" for h in (ta.seed_branch.subdomains if ta.seed_branch else []))
    assert not any(h.host == "www.beta.com" for h in (ta.seed_branch.subdomains if ta.seed_branch else []))
    assert any(h.host == "www.beta.com" for h in (tb.seed_branch.subdomains if tb.seed_branch else []))


def test_full_context_includes_tree() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "ctx-tree.com"}).json()
        client.post(
            "/api/v1/findings/",
            json={
                "engagement_id": eng["id"],
                "finding_type": "subdomain",
                "title": "a.ctx-tree.com",
                "source_tool": "subfinder_scan",
            },
        )
        ctx = client.get(
            "/api/v1/hybrid/context/full",
            params={"engagement_id": eng["id"]},
        )
        assert ctx.status_code == 200
        data = ctx.json()
        assert data["attack_surface_tree_text"]
        assert data["attack_surface_tree"] is not None
        assert data["attack_surface_tree"]["seed"] == "ctx-tree.com"
