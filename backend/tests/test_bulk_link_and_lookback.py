"""Bulk graph links (platform_graph_link_many) + finalize look-back rework.

Covers: one-call bulk edge persistence (fan + list form), the auto-built
skeleton edges (subdomain->domain, host->port->service, host->tech) added to
ingestion, and the reworked finalize_readiness look-back (orphan/unexplored
assets, untested hypotheses) that replaced the old hard proof-gate.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.engagement import EngagementCreateRequest
from pentest_platform.schemas.engagement_graph import AssetType
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.engagement_store import get_engagement_store
from pentest_platform.services.finalize_readiness import compute_finalize_readiness
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.open_loops import build_open_loops, find_orphan_and_unexplored
from pentest_platform.services.operator_memory import link_assets_many, record_think


def test_bulk_link_fan_form_one_call_many_edges() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "bulklink.test"}).json()
        eid = eng["id"]
        resp = client.post(
            "/api/v1/hybrid/graph/link-many",
            json={
                "engagement_id": eid,
                "source": "domain:bulklink.test",
                "relation": "has_subdomain",
                "targets": [
                    "subdomain:a.bulklink.test",
                    "subdomain:b.bulklink.test",
                    "subdomain:c.bulklink.test",
                ],
                "evidence": "subfinder enumeration",
                "evidence_grade": "observed",
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["count"] == 3
        assert data["observed_count"] == 3
        assert data["hypothesis_count"] == 0
        assert data["finding_id"]

        edges = get_engagement_graph().list_edges(engagement_id=eid, relationship="has_subdomain")
        assert len(edges) == 3


def test_bulk_link_list_form_mixed_relations_and_grades() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "bulklist.test"}).json()
        eid = eng["id"]
        resp = client.post(
            "/api/v1/hybrid/graph/link-many",
            json={
                "engagement_id": eid,
                "links": [
                    {
                        "source": "host:x.bulklist.test",
                        "target": "ip:9.9.9.9",
                        "relation": "resolves_to_hint",
                        "evidence": "same ASN",
                        "evidence_grade": "observed",
                    },
                    {
                        "source": "host:y.bulklist.test",
                        "target": "ip:9.9.9.9",
                        "relation": "shares_infra",
                        "evidence": "same ASN, unconfirmed",
                        "evidence_grade": "inferred",
                    },
                ],
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["count"] == 2
        assert data["observed_count"] == 1
        assert data["hypothesis_count"] == 1
        rels = {e["relationship"] for e in data["edges"]}
        assert "resolves_to_hint" in rels
        assert "hypothesis_shares_infra" in rels


def test_bulk_link_requires_evidence_per_edge() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "bulknoev.test"}).json()
        eid = eng["id"]
        resp = client.post(
            "/api/v1/hybrid/graph/link-many",
            json={
                "engagement_id": eid,
                "source": "a.bulknoev.test",
                "relation": "same_app_as",
                "targets": ["b.bulknoev.test"],
                "evidence": "",
            },
        )
        assert resp.status_code == 400


def test_link_assets_many_direct_call() -> None:
    """Same coverage via direct service call (bypasses HTTP layer)."""
    eng = get_engagement_store().create(EngagementCreateRequest(target="directbulk.test"))
    result = link_assets_many(
        engagement_id=eng.id,
        source="domain:directbulk.test",
        relation="has_subdomain",
        targets=["subdomain:d1.directbulk.test", "subdomain:d2.directbulk.test"],
        evidence="subfinder",
        evidence_grade="observed",
    )
    assert result["count"] == 2
    assert result["hint"]


def test_auto_skeleton_edges_built_on_ingest() -> None:
    """subdomain->domain, host->port->service, host->tech built without operator calls."""
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "skeleton.test"}).json()
        eid = eng["id"]

        findings = [
            Finding(
                engagement_id=eid,
                finding_type=FindingType.SUBDOMAIN,
                title="sub1.skeleton.test",
                target="skeleton.test",
                source_tool="subfinder_scan",
                metadata={"hostname": "sub1.skeleton.test"},
            ),
            Finding(
                engagement_id=eid,
                finding_type=FindingType.SERVICE,
                title="10.0.0.5:22/tcp OpenSSH 8.9",
                target="10.0.0.5",
                source_tool="nmap_service_scan",
                metadata={"port": "22", "protocol": "tcp", "service": "OpenSSH 8.9", "ip": "10.0.0.5"},
            ),
            Finding(
                engagement_id=eid,
                finding_type=FindingType.TECHNOLOGY,
                title="nginx",
                target="http://sub1.skeleton.test",
                source_tool="httpx_probe",
                metadata={"hostname": "sub1.skeleton.test", "url": "http://sub1.skeleton.test"},
            ),
        ]
        get_engagement_graph().ingest_many(findings)

        edges = get_engagement_graph().list_edges(engagement_id=eid)
        rels = {e.relationship for e in edges}
        assert "subdomain_of" in rels, "subdomain should auto-link to parent domain"
        assert "has_port" in rels, "SERVICE finding should still build host->port skeleton"
        assert "runs_service" in rels, "port should link to the service node"
        assert "runs_tech" in rels, "technology should link to the host it was seen on"

        # No SERVICE/TECHNOLOGY node should be an orphan any more.
        orphans, _ = find_orphan_and_unexplored(eid)
        orphan_labels = {n.label for n in orphans}
        assert "10.0.0.5:22/tcp OpenSSH 8.9" not in orphan_labels
        assert "nginx" not in orphan_labels


def test_open_loops_surfaces_orphan_and_unexplored() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "orphanloop.test"}).json()
        eid = eng["id"]

        # A lone node with no edges at all -> orphan.
        get_engagement_graph().ensure_node(
            engagement_id=eid,
            asset_type=AssetType.HOST,
            label="island.orphanloop.test",
        )
        loops = build_open_loops(eid, max_loops=20)
        loop_ids = {loop["id"] for loop in loops["loops"]}
        assert "orphan_assets" in loop_ids
        orphan_loop = next(loop for loop in loops["loops"] if loop["id"] == "orphan_assets")
        assert "island.orphanloop.test" in orphan_loop["targets"]


def test_finalize_readiness_is_never_blocking_and_has_look_back() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "lookback.test"}).json()
        eid = eng["id"]

    # Untested hypothesis: recorded, nothing derived_from's it yet.
    record_think(
        engagement_id=eid,
        hypothesis="erp and ess share auth",
        plan="compare cookies",
        evidence="same IP",
    )
    # An unexplored host: in the graph, never in tool_coverage.
    get_engagement_graph().ensure_node(
        engagement_id=eid,
        asset_type=AssetType.HOST,
        label="never-probed.lookback.test",
    )

    readiness = compute_finalize_readiness(engagement_id=eid)
    assert readiness["can_finalize"] is True  # never a hard block, by design
    lb = readiness["look_back"]
    assert lb["untested_hypothesis_count"] >= 1
    assert "never-probed.lookback.test" in lb["unexplored_assets"]
    # blocked_by is now purely advisory data, not a gate.
    assert isinstance(readiness["blocked_by"], list)


def test_untested_hypothesis_becomes_tested_once_referenced() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "hyptested.test"}).json()
        eid = eng["id"]

    think = record_think(engagement_id=eid, hypothesis="shared backend", evidence="seen twice")
    hyp_id = think["finding_id"]

    before = compute_finalize_readiness(engagement_id=eid)
    assert any(h["finding_id"] == hyp_id for h in before["look_back"]["untested_hypotheses"])

    # A later finding cites the hypothesis as derived_from -> now "tested".
    get_findings_store().add(
        Finding(
            engagement_id=eid,
            finding_type=FindingType.OBSERVATION,
            title="Confirmed shared backend via response timing",
            target="hyptested.test",
            source_tool="test",
            metadata={"derived_from": [hyp_id]},
        )
    )
    after = compute_finalize_readiness(engagement_id=eid)
    assert not any(h["finding_id"] == hyp_id for h in after["look_back"]["untested_hypotheses"])
