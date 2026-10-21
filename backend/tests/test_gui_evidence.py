"""Read-only evidence browsing must retain records beyond presentation filters."""
from types import SimpleNamespace

from fastapi.testclient import TestClient

from osprey.main import app
from osprey.schemas.engagement import EngagementCreateRequest
from osprey.schemas.finding import Finding
from osprey.schemas.observation import Observation
from osprey.schemas.engagement_graph import AssetNode, AssetType, AssetEdge
from osprey.services.engagement_store import get_engagement_store
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store


def test_evidence_pagination_and_original_record_scoping():
    engagement=get_engagement_store().create(EngagementCreateRequest(target="gui-evidence.test"))
    other=get_engagement_store().create(EngagementCreateRequest(target="gui-evidence-other.test"))
    get_findings_store().add_many([Finding(engagement_id=engagement.id,finding_type="observation",title=f"raw note {i}",target="gui-evidence.test",evidence="complete original output") for i in range(12)])
    get_observation_store().record_many([Observation(engagement_id=engagement.id,type="url",target="gui-evidence.test",details={"url":f"https://gui-evidence.test/{i}"}) for i in range(12)])
    with TestClient(app) as client:
        for path,collection in (("findings","findings"),("observations","observations")):
            query=f"engagement_id={engagement.id}&exclude_noise=false&limit=5"
            first=client.get(f"/api/v1/{path}/?{query}").json()[collection]
            second=client.get(f"/api/v1/{path}/?{query}&offset=5").json()[collection]
            assert len(first)==len(second)==5
            assert not {r["id"] for r in first}.intersection(r["id"] for r in second)
            record_path=f"/api/v1/findings/record/{first[0]['id']}" if path=="findings" else f"/api/v1/observations/{first[0]['id']}"
            assert client.get(f"{record_path}?engagement_id={engagement.id}").status_code==200
            assert client.get(f"{record_path}?engagement_id={other.id}").status_code==404
        assert client.get(f"/api/v1/observations/?engagement_id={engagement.id}&q=%2F11").json()["total"]==1
        assert client.get("/api/v1/report/missing-record").status_code==404
        assert client.get("/api/v1/report/missing-record/markdown").status_code==404


def test_graph_record_preservation_does_not_filter_labels_or_static_assets(monkeypatch):
    from osprey.services import visualization
    nodes=[AssetNode(id="domain:test",asset_type=AssetType.DOMAIN,label="test.example",metadata={"source":"retained"},observation_ids=["obs1"],source_tools=["httpx"]),
           AssetNode(id="url:static",asset_type=AssetType.URL,label="https://test.example/image.png"),
           AssetNode(id="host:legacy",asset_type=AssetType.HOST,label="/legacy/label/"),
           AssetNode(id="url:long",asset_type=AssetType.URL,label="https://test.example/"+"a"*700)]
    edges=[AssetEdge(source_id="url:static",target_id="domain:test",relationship="hosted_on",observation_ids=["obs1"])]
    monkeypatch.setattr(visualization,"get_engagement_graph",lambda:SimpleNamespace(list_nodes=lambda **kw:nodes,list_edges=lambda **kw:edges))
    monkeypatch.setattr(visualization,"_build_finding_map",lambda eid:{})
    graph=visualization.generate_cytoscape_json("test",preserve_records=True,exclude_urls=False)
    assert len(graph["nodes"])==4
    assert len(graph["nodes"][-1]["data"]["label"])>700
    assert graph["nodes"][0]["data"]["metadata"]=={"source":"retained"}
    assert graph["edges"][0]["data"]["observation_ids"]==["obs1"]


def test_graph_risk_explains_findings_without_propagating_to_neighbors(monkeypatch):
    from osprey.services import visualization
    findings = [
        Finding(id="risk", finding_type="vulnerability", title="Observed issue", target="192.0.2.1", claim_severity="high", confidence="likely", node_id="port:192.0.2.1:443"),
        Finding(id="fact", finding_type="host", title="Discovery", target="sibling.test", claim_severity="critical"),
        Finding(id="failed", finding_type="vulnerability", title="Tool error", target="sibling.test", claim_severity="critical", tags=["tool_error"]),
    ]
    monkeypatch.setattr(visualization, "get_findings_store", lambda: SimpleNamespace(list=lambda **kw: findings))
    refs = visualization._build_finding_map("test")
    assert refs["ip:192.0.2.1"][0]["id"] == "risk"
    assert refs["port:192.0.2.1:443"][0]["confidence"] == "likely"
    assert "host:sibling.test" not in refs
    assert visualization._build_severity_map("test")["ip:192.0.2.1"] == "high"
