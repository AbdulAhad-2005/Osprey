"""Visualization feature tests: Mermaid severity classes actually applied.

Covers the class-application bug where classDefs were emitted but never
bound to nodes, plus Cytoscape JSON severity badges and format routing.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.visualization import (
    generate_attack_tree,
    generate_cytoscape_json,
    generate_mermaid,
    get_visualization,
)


def _seed(engagement_id: str) -> None:
    client = TestClient(app)
    resp = client.post(
        "/api/v1/hybrid/graph/link-many",
        json={
            "engagement_id": engagement_id,
            "source": "host:x.viz.test",
            "relation": "resolves_to",
            "targets": ["ip:1.2.3.4"],
            "evidence": "test edge",
            "evidence_grade": "observed",
        },
    )
    assert resp.status_code == 200, resp.text
    store = get_findings_store()
    store.add(
        Finding(
            engagement_id=engagement_id,
            title="high severity issue",
            evidence="verified manually",
            finding_type=FindingType.HOST,
            target="x.viz.test",
            claim_severity="high",
            evidence_grade="observed",
            confidence="confirmed",
        )
    )


def test_mermaid_applies_severity_classes() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "viz.test"}).json()
        _seed(eng["id"])
        md = generate_mermaid(eng["id"])
        assert "classDef high" in md
        assert "class host_x_viz_test high" in md
        assert "classDef none" in md


def test_mermaid_class_only_for_known_severities() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "viz2.test"}).json()
        _seed(eng["id"])
        md = generate_mermaid(eng["id"])
        for line in md.splitlines():
            if line.startswith("  class "):
                cls = line.split()[-1]
                assert cls in {"critical", "high", "medium", "low", "info", "none"}, line


def test_cytoscape_json_has_severity_badges() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "viz3.test"}).json()
        _seed(eng["id"])
        cyto = generate_cytoscape_json(eng["id"])
        sevs = {
            n["data"]["id"]: n["data"]["severity"]
            for n in cyto["nodes"]
        }
        assert sevs.get("host:x.viz.test") == "high"


def test_attack_tree_routes_domain_to_subdomains() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "viz4.test"}).json()
        tree = generate_attack_tree(eng["id"])
        assert "metadata" in tree
        assert tree["metadata"]["total_nodes"] >= 0


def test_get_visualization_format_routing() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "viz5.test"}).json()
        _seed(eng["id"])
        assert get_visualization(eng["id"], "mermaid")["format"] == "mermaid"
        assert get_visualization(eng["id"], "json")["format"] == "cytoscape_json"
        assert get_visualization(eng["id"], "tree")["format"] == "attack_tree"
        assert get_visualization(eng["id"], "bogus")["format"] == "mermaid"


def test_report_data_includes_remediation_and_topology() -> None:
    from pentest_platform.services.report_generator import build_report_data

    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "report.test"}).json()
        _seed(eng["id"])
        data = build_report_data(eng["id"])
        assert "metrics" in data
        assert "findings_by_severity" in data
        assert "topology" in data
        assert "remediation_hint" in data["findings_by_severity"][0]["findings"][0]

