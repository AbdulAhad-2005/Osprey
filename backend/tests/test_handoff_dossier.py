"""Self-contained handoff dossier for a zero-context downstream agent."""

from __future__ import annotations

from fastapi.testclient import TestClient
from osprey.main import app
from osprey.schemas.finding import (
    ClaimSeverity,
    Finding,
    FindingConfidence,
    FindingType,
)
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.findings_store import get_findings_store


def _seed(eid: str) -> None:
    store = get_findings_store()
    graph = get_engagement_graph()
    findings = [
        Finding(
            engagement_id=eid, run_id="r1", finding_type=FindingType.SUBDOMAIN,
            title="app.dossier.test", target="dossier.test", source_tool="subfinder",
            metadata={"ip": "10.0.0.5"},
        ),
        Finding(
            engagement_id=eid, run_id="r1", finding_type=FindingType.PORT,
            title="app.dossier.test:443", target="app.dossier.test", source_tool="naabu",
            metadata={"hostname": "app.dossier.test", "port": 443, "protocol": "tcp"},
        ),
        Finding(
            engagement_id=eid, run_id="r1", finding_type=FindingType.TECHNOLOGY,
            title="nginx", target="app.dossier.test", source_tool="whatweb",
            metadata={"host": "app.dossier.test", "technology": "nginx"},
        ),
        Finding(
            engagement_id=eid, run_id="r1", finding_type=FindingType.SECRET,
            title="AWS access key id exposed: AKIA...", target="app.dossier.test",
            evidence="AKIAIOSFODNN7EXAMPLE", confidence=FindingConfidence.CONFIRMED,
            claim_severity=ClaimSeverity.HIGH, source_tool="js_recon",
        ),
        Finding(
            engagement_id=eid, run_id="r1", finding_type=FindingType.VULNERABILITY,
            title="Exposed admin panel", target="app.dossier.test",
            evidence="200 OK /admin", confidence=FindingConfidence.CONFIRMED,
            claim_severity=ClaimSeverity.HIGH, source_tool="nuclei",
        ),
    ]
    store.add_many(findings)
    graph.ingest_many(findings)


def test_handoff_dossier_is_self_contained() -> None:
    with TestClient(app) as client:
        eid = client.post("/api/v1/engagements/", json={"target": "dossier.test"}).json()["id"]
        _seed(eid)
        dossier = client.get("/api/v1/findings/handoff", params={"engagement_id": eid}).json()

    assert dossier["target"] == "dossier.test"
    assert dossier["totals"]["findings"] >= 5

    # Credentials/secrets are broken out for the exploit agent.
    cred_titles = " ".join(c["title"] for c in dossier["credentials"])
    assert "AWS access key" in cred_titles
    assert all(c["confidence"] for c in dossier["credentials"])  # provenance present

    # Vulnerabilities broken out with severity + evidence.
    assert any(v["title"] == "Exposed admin panel" and v["claim_severity"] == "high"
               for v in dossier["vulnerabilities"])

    # Asset inventory reconstructs host attributes from the graph alone.
    app_asset = next(a for a in dossier["assets"] if a["label"] == "app.dossier.test")
    assert app_asset["ip"] == "10.0.0.5"
    assert "nginx" in app_asset["technologies"]
    assert any(str(p["port"]) == "443" for p in app_asset["ports"])
    assert app_asset["source_tool"] == "subfinder"  # provenance on the asset

    # Every finding carries full provenance — nothing a next agent needs is dropped.
    for f in dossier["findings"]:
        assert f["source_tool"] is not None
        assert f["confidence"]
        assert "occurrence_count" in f

    # The relationship graph is included so pivots survive the handoff.
    assert dossier["graph"]["nodes"]
    assert dossier["graph"]["edges"]
