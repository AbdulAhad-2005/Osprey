from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.tools import ToolCategory
from pentest_platform.services.tool_registry import list_registered_tools

client = TestClient(app)


# ---------------------------------------------------------------------------
# Tool catalog tests
# ---------------------------------------------------------------------------

def test_list_tools_returns_all_registered_tools() -> None:
    response = client.get("/api/v1/tools/")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == len(list_registered_tools())
    # Check key fields exist
    first = payload[0]
    assert {"name", "category", "description", "installed", "safety_level", "mcp_server"} <= set(first)


def test_list_tools_can_filter_by_category() -> None:
    response = client.get("/api/v1/tools/", params={"category": ToolCategory.NETWORK})

    assert response.status_code == 200
    payload = response.json()
    assert payload
    assert {tool["category"] for tool in payload} == {ToolCategory.NETWORK}


def test_list_tools_can_filter_by_recon() -> None:
    response = client.get("/api/v1/tools/", params={"category": ToolCategory.RECON})

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 9  # 9 recon tools


def test_tool_catalog_summary_matches_tools() -> None:
    response = client.get("/api/v1/tools/catalog")

    assert response.status_code == 200
    payload = response.json()
    tools = payload["tools"]
    summary = payload["summary"]
    assert summary["total"] == len(tools)
    assert summary["installed"] + summary["missing"] == summary["total"]
    assert summary["by_category"]["network"] >= 1


def test_read_tool_returns_one_tool() -> None:
    response = client.get("/api/v1/tools/nmap_syn_scan")

    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == "nmap_syn_scan"
    assert payload["category"] == "network"
    assert payload["mcp_server"] == "network"


def test_read_tool_returns_404_for_unknown_tool() -> None:
    response = client.get("/api/v1/tools/not-a-real-tool")

    assert response.status_code == 404


def test_all_tools_have_mcp_server() -> None:
    """Every registered tool must map to an MCP server."""
    response = client.get("/api/v1/tools/")
    payload = response.json()
    for tool in payload:
        assert "mcp_server" in tool, f"Tool {tool['name']} missing mcp_server"
        assert tool["mcp_server"], f"Tool {tool['name']} has empty mcp_server"


def test_tools_by_server() -> None:
    response = client.get("/api/v1/tools/by-server/network")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) >= 10  # 15 network tools
    assert all(t["mcp_server"] == "network" for t in payload)


# ---------------------------------------------------------------------------
# Engagement tests
# ---------------------------------------------------------------------------

def test_create_and_list_engagement() -> None:
    # Create
    response = client.post("/api/v1/engagements/", json={
        "target": "10.0.0.1",
        "name": "test engagement",
    })
    assert response.status_code == 201
    eng = response.json()
    assert eng["target"] == "10.0.0.1"
    eng_id = eng["id"]

    # List
    response = client.get("/api/v1/engagements/")
    assert response.status_code == 200
    assert any(e["id"] == eng_id for e in response.json())

    # Get by ID
    response = client.get(f"/api/v1/engagements/{eng_id}")
    assert response.status_code == 200
    assert response.json()["id"] == eng_id


def test_get_engagement_returns_404() -> None:
    response = client.get("/api/v1/engagements/nonexistent")
    assert response.status_code == 404


def test_delete_engagement() -> None:
    # Create
    response = client.post("/api/v1/engagements/", json={"target": "10.0.0.2"})
    eng_id = response.json()["id"]

    # Delete
    response = client.delete(f"/api/v1/engagements/{eng_id}")
    assert response.status_code == 204

    # Verify gone
    response = client.get(f"/api/v1/engagements/{eng_id}")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Governance tests
# ---------------------------------------------------------------------------

def test_governance_denies_gated_tool_without_exploitation() -> None:
    """sqlmap (GATED) should be denied when exploitation is disabled."""
    # Create engagement with exploitation disabled
    response = client.post("/api/v1/engagements/", json={
        "target": "10.0.0.1",
        "rules_of_engagement": {
            "allow_exploitation": False,
        },
    })
    eng_id = response.json()["id"]

    # Try to execute a GATED tool
    response = client.post("/api/v1/mcp/execute", json={
        "tool_name": "sqlmap_scan",
        "params": {"url": "http://10.0.0.1/vuln?id=1"},
        "engagement_id": eng_id,
    })
    assert response.status_code == 403


def test_governance_allows_passive_tool() -> None:
    """subfinder (PASSIVE) should always be allowed."""
    response = client.post("/api/v1/engagements/", json={
        "target": "example.com",
        "rules_of_engagement": {
            "scope": {
                "in_scope_targets": ["example.com"],
            },
        },
    })
    eng_id = response.json()["id"]

    # subfinder is PASSIVE — governance allows it, but MCP server may not be running
    # We just test that governance passes (the MCP call itself may fail)
    response = client.post("/api/v1/mcp/execute", json={
        "tool_name": "subfinder_scan",
        "params": {"domain": "example.com"},
        "engagement_id": eng_id,
    })
    # 500 = MCP server not running (expected in test env)
    # 403 = governance denied (would mean governance is broken)
    assert response.status_code != 403


def test_governance_denies_out_of_scope_target() -> None:
    response = client.post("/api/v1/engagements/", json={
        "target": "10.0.0.1",
        "rules_of_engagement": {
            "scope": {
                "out_of_scope": ["10.0.0.99"],
            },
        },
    })
    eng_id = response.json()["id"]

    response = client.post("/api/v1/mcp/execute", json={
        "tool_name": "subfinder_scan",
        "params": {"domain": "10.0.0.99"},
        "engagement_id": eng_id,
    })
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Audit log tests
# ---------------------------------------------------------------------------

def test_audit_log_records_denied_action() -> None:
    # Create engagement with exploitation disabled
    response = client.post("/api/v1/engagements/", json={
        "target": "10.0.0.1",
        "rules_of_engagement": {"allow_exploitation": False},
    })
    eng_id = response.json()["id"]

    # Attempt gated tool
    client.post("/api/v1/mcp/execute", json={
        "tool_name": "sqlmap_scan",
        "params": {"url": "http://10.0.0.1/vuln"},
        "engagement_id": eng_id,
    })

    # Check audit log
    response = client.get("/api/v1/audit/", params={"engagement_id": eng_id})
    assert response.status_code == 200
    entries = response.json()
    assert len(entries) >= 1
    assert entries[-1]["action"]["governance_decision"] == "denied"
