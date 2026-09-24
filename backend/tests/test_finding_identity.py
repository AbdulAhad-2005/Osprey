"""Occurrence-vs-canonical finding identity.

Locks in the storage contract that replaced the old lossy content-hash dedup:
- the same fact seen by two tools becomes ONE canonical finding with BOTH provenances
  (nothing silently dropped, no provenance lost),
- genuinely distinct facts never collapse,
- a stronger later observation upgrades the canonical grade,
- writes report explicit stored/merged counts.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from osprey.main import app
from osprey.schemas.finding import (
    ClaimSeverity,
    Finding,
    FindingConfidence,
    FindingType,
)
from osprey.services.findings_store import get_findings_store


def _engagement(target: str = "identity.test") -> str:
    with TestClient(app) as client:
        return client.post("/api/v1/engagements/", json={"target": target}).json()["id"]


def test_same_fact_two_tools_one_canonical_two_occurrences() -> None:
    eid = _engagement("dedup-prov.test")
    store = get_findings_store()

    from_subfinder = Finding(
        engagement_id=eid,
        run_id="r1",
        finding_type=FindingType.SUBDOMAIN,
        title="api.dedup-prov.test",
        target="dedup-prov.test",
        source_tool="subfinder",
    )
    from_crtsh = Finding(
        engagement_id=eid,
        run_id="r1",
        finding_type=FindingType.SUBDOMAIN,
        title="api.dedup-prov.test",
        target="dedup-prov.test",
        source_tool="crt_sh_query",
    )

    r1 = store.add_many_result([from_subfinder])
    r2 = store.add_many_result([from_crtsh])

    assert r1.stored == 1 and r1.merged == 0
    # Second tool did NOT create a new finding, and was NOT silently dropped.
    assert r2.stored == 0 and r2.merged == 1

    listed = store.list(engagement_id=eid, limit=50)
    subs = [f for f in listed if f.finding_type == FindingType.SUBDOMAIN]
    assert len(subs) == 1  # one canonical

    canonical_id = subs[0].id
    assert store.recurrence(finding_id=canonical_id) == 2
    provenance = store.occurrences(finding_id=canonical_id)
    tools = {o["source_tool"] for o in provenance}
    assert tools == {"subfinder", "crt_sh_query"}  # BOTH provenances preserved


def test_distinct_facts_do_not_collapse() -> None:
    eid = _engagement("distinct.test")
    store = get_findings_store()
    # Two sibling subdomains discovered under the same seed (same target) must not
    # collapse — the old dedup anchored on target and lost one of them.
    store.add_many(
        [
            Finding(
                engagement_id=eid,
                finding_type=FindingType.HOST,
                title="one.distinct.test",
                target="distinct.test",
                source_tool="domain_hunter",
            ),
            Finding(
                engagement_id=eid,
                finding_type=FindingType.HOST,
                title="two.distinct.test",
                target="distinct.test",
                source_tool="domain_hunter",
            ),
        ]
    )
    hosts = {f.title for f in store.list(engagement_id=eid, limit=50) if f.finding_type == FindingType.HOST}
    assert hosts == {"one.distinct.test", "two.distinct.test"}


def test_stronger_observation_upgrades_confidence() -> None:
    eid = _engagement("upgrade.test")
    store = get_findings_store()
    # Same vulnerability, first inferred, later observed with a real body → upgrade.
    weak = Finding(
        engagement_id=eid,
        finding_type=FindingType.VULNERABILITY,
        title="Exposed admin panel",
        target="upgrade.test",
        evidence="hostname match only",
        confidence=FindingConfidence.HYPOTHESIS,
        claim_severity=ClaimSeverity.MEDIUM,
    )
    strong = weak.model_copy(
        update={
            "confidence": FindingConfidence.CONFIRMED,
            "claim_severity": ClaimSeverity.HIGH,
            "source_tool": "manual_probe",
        }
    )
    store.add(weak)
    store.add(strong)

    vulns = [f for f in store.list(engagement_id=eid, limit=50) if f.finding_type == FindingType.VULNERABILITY]
    assert len(vulns) == 1
    assert vulns[0].confidence == FindingConfidence.CONFIRMED
    assert vulns[0].claim_severity == ClaimSeverity.HIGH


def test_node_carries_provenance_and_nested_metadata() -> None:
    from osprey.schemas.engagement_graph import AssetType
    from osprey.services.engagement_graph import get_engagement_graph

    eid = _engagement("nodeprov.test")
    store = get_findings_store()
    graph = get_engagement_graph()

    f = Finding(
        engagement_id=eid,
        run_id="r1",
        finding_type=FindingType.SUBDOMAIN,
        title="host.nodeprov.test",
        target="nodeprov.test",
        source_tool="subfinder",
        confidence=FindingConfidence.CONFIRMED,
        # Nested metadata must survive on the node, not be flattened away.
        metadata={"ip": "10.0.0.9", "banner": {"server": "nginx", "ports": [80, 443]}},
    )
    store.add(f)
    graph.ingest_finding(f)

    nodes = {n.id: n for n in graph.list_nodes(engagement_id=eid, asset_type=AssetType.SUBDOMAIN)}
    node = nodes["subdomain:host.nodeprov.test"]
    assert node.source_tool == "subfinder"  # provenance recorded on the node
    assert node.confidence == "confirmed"
    assert node.metadata.get("banner", {}).get("ports") == [80, 443]  # nested kept

    # The finding is linked back to its primary graph node.
    linked = [f for f in store.list(engagement_id=eid, limit=50) if f.title == "host.nodeprov.test"][0]
    stored_node_id = store.node_id_for(finding_id=linked.id)
    assert stored_node_id == "subdomain:host.nodeprov.test"


def test_occurrences_endpoint_exposes_provenance() -> None:
    with TestClient(app) as client:
        eid = client.post("/api/v1/engagements/", json={"target": "occ-api.test"}).json()["id"]
        base = {
            "engagement_id": eid,
            "run_id": "r1",
            "finding_type": "subdomain",
            "title": "www.occ-api.test",
            "target": "occ-api.test",
        }
        a = client.post("/api/v1/findings/", json={**base, "source_tool": "subfinder"}).json()
        b = client.post("/api/v1/findings/", json={**base, "source_tool": "amass"}).json()
        # Same fact, two tools → one canonical id.
        assert a["id"] == b["id"]

        occ = client.get(f"/api/v1/findings/{a['id']}/occurrences").json()
        assert occ["recurrence"] == 2
        assert {o["source_tool"] for o in occ["occurrences"]} == {"subfinder", "amass"}


def test_same_tech_on_two_hosts_stays_distinct() -> None:
    eid = _engagement("tech.test")
    store = get_findings_store()
    store.add_many(
        [
            Finding(
                engagement_id=eid,
                finding_type=FindingType.TECHNOLOGY,
                title="nginx",
                target="a.tech.test",
                metadata={"host": "a.tech.test"},
                source_tool="whatweb",
            ),
            Finding(
                engagement_id=eid,
                finding_type=FindingType.TECHNOLOGY,
                title="nginx",
                target="b.tech.test",
                metadata={"host": "b.tech.test"},
                source_tool="whatweb",
            ),
        ]
    )
    techs = [f for f in store.list(engagement_id=eid, limit=50) if f.finding_type == FindingType.TECHNOLOGY]
    assert len(techs) == 2  # same label, different hosts → two facts
