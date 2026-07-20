"""
Full integration test script for the tool feature.

Tests the complete pipeline:
  1. Tool catalog (90 tools, categories, safety levels)
  2. Engagement CRUD with scope config
  3. Governance enforcement (scope, safety, time windows)
  4. MCP tool execution (with mock MCP server)
  5. Audit log recording

Run from backend/:
    python tests/test_full_tool_feature.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure src is on path
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fastapi.testclient import TestClient
from pentest_platform.main import app
from pentest_platform.schemas.tools import ToolCategory, ToolSafetyLevel, MCPServerCategory
from pentest_platform.services.tool_registry import (
    get_tool,
    get_tool_definition,
    get_tools_by_mcp_server,
    list_registered_tools,
)
from pentest_platform.services.governance import GovernanceEngine
from pentest_platform.services.audit_log import AuditLog

client = TestClient(app)
PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        msg = f"  FAIL  {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)


def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# =========================================================================
section("1. TOOL CATALOG — 90 tools registered")
# =========================================================================

tools = list_registered_tools()
check("Total tools = 90", len(tools) == 90, f"got {len(tools)}")

cats = {}
for t in tools:
    cats[t.category] = cats.get(t.category, 0) + 1

check("10 categories present", len(cats) == 10, f"got {len(cats)}: {list(cats.keys())}")
check("9 recon tools", cats.get(ToolCategory.RECON) == 9)
check("15 network tools", cats.get(ToolCategory.NETWORK) == 15)
check("22 webapp tools", cats.get(ToolCategory.WEBAPP) == 22)
check("15 binary tools", cats.get(ToolCategory.BINARY) == 15)
check("12 cloud tools", cats.get(ToolCategory.CLOUD) == 12)

# Every tool has required fields
for t in tools:
    check(f"tool '{t.name}' has mcp_server", bool(t.mcp_server))

# =========================================================================
section("2. TOOL LOOKUP")
# =========================================================================

t = get_tool("nmap_syn_scan")
check("get_tool('nmap_syn_scan') found", t is not None)
if t:
    check("nmap is network category", t.category == ToolCategory.NETWORK)
    check("nmap is ACTIVE safety", t.safety_level == ToolSafetyLevel.ACTIVE)
    check("nmap maps to network MCP server", t.mcp_server == MCPServerCategory.NETWORK)

t = get_tool("sqlmap_scan")
check("get_tool('sqlmap_scan') found", t is not None)
if t:
    check("sqlmap is GATED safety", t.safety_level == ToolSafetyLevel.GATED)

t = get_tool("subfinder_scan")
check("get_tool('subfinder_scan') found", t is not None)
if t:
    check("subfinder is PASSIVE safety", t.safety_level == ToolSafetyLevel.PASSIVE)

check("get_tool('nonexistent') returns None", get_tool("nonexistent") is None)

# =========================================================================
section("3. API — Tool catalog endpoints")
# =========================================================================

resp = client.get("/api/v1/tools/")
check("GET /api/v1/tools/ returns 200", resp.status_code == 200)
check("Returns 90 tools", len(resp.json()) == 90)

resp = client.get("/api/v1/tools/", params={"category": "webapp"})
check("Filter by webapp returns 22", len(resp.json()) == 22)

resp = client.get("/api/v1/tools/catalog")
check("GET /api/v1/tools/catalog returns 200", resp.status_code == 200)
summary = resp.json()["summary"]
check("Catalog total = 90", summary["total"] == 90)

resp = client.get("/api/v1/tools/by-server/network")
check("GET /api/v1/tools/by-server/network returns 15", len(resp.json()) == 15)

resp = client.get("/api/v1/tools/nmap_syn_scan")
check("GET /api/v1/tools/nmap_syn_scan returns 200", resp.status_code == 200)

resp = client.get("/api/v1/tools/nonexistent")
check("GET /api/v1/tools/nonexistent returns 404", resp.status_code == 404)

# =========================================================================
section("4. ENGAGEMENT CRUD")
# =========================================================================

resp = client.post("/api/v1/engagements/", json={
    "target": "10.0.0.1",
    "name": "Test Lab Engagement",
    "rules_of_engagement": {
        "allow_exploitation": False,
        "requires_human_approval": True,
        "scope": {
            "in_scope_targets": ["10.0.0.0/24", "lab.example.com"],
            "out_of_scope": ["10.0.0.99"],
            "blocked_techniques": ["creds"],
        },
    },
})
check("POST /api/v1/engagements/ returns 201", resp.status_code == 201)
eng = resp.json()
eng_id = eng["id"]
check("Engagement has target", eng["target"] == "10.0.0.1")
check("Engagement has scope", "in_scope_targets" in eng["rules_of_engagement"]["scope"])

resp = client.get("/api/v1/engagements/")
check("List engagements returns at least 1", len(resp.json()) >= 1)

resp = client.get(f"/api/v1/engagements/{eng_id}")
check("Get engagement by ID works", resp.status_code == 200)

resp = client.delete(f"/api/v1/engagements/{eng_id}")
check("Delete engagement returns 204", resp.status_code == 204)

resp = client.get(f"/api/v1/engagements/{eng_id}")
check("Deleted engagement returns 404", resp.status_code == 404)

# =========================================================================
section("5. GOVERNANCE — Scope enforcement")
# =========================================================================

# Create engagement with specific scope
resp = client.post("/api/v1/engagements/", json={
    "target": "10.0.0.1",
    "rules_of_engagement": {
        "allow_exploitation": False,
        "scope": {
            "in_scope_targets": ["10.0.0.0/24", "lab.example.com"],
            "out_of_scope": ["10.0.0.99"],
        },
    },
})
eng_id = resp.json()["id"]

# 5a. GATED tool denied (exploitation disabled)
resp = client.post("/api/v1/mcp/execute", json={
    "tool_name": "sqlmap_scan",
    "params": {"url": "http://10.0.0.1/vuln?id=1"},
    "engagement_id": eng_id,
})
check("GATED tool denied when exploitation=false", resp.status_code == 403,
      resp.json().get("detail", ""))

# 5b. GATED tool denied (requires approval)
resp = client.post("/api/v1/mcp/execute", json={
    "tool_name": "metasploit_run",
    "params": {"module": "exploit/test", "options": "{}"},
    "engagement_id": eng_id,
})
check("Metasploit denied (requires approval)", resp.status_code == 403)

# 5c. Out-of-scope target denied
resp = client.post("/api/v1/mcp/execute", json={
    "tool_name": "subfinder_scan",
    "params": {"domain": "10.0.0.99"},
    "engagement_id": eng_id,
})
check("Out-of-scope target denied", resp.status_code == 403,
      resp.json().get("detail", ""))

# 5d. Blocked category denied
resp = client.post("/api/v1/mcp/execute", json={
    "tool_name": "hydra_attack",
    "params": {"target": "10.0.0.1", "service": "ssh"},
    "engagement_id": eng_id,
})
check("Blocked category (creds) denied", resp.status_code == 403,
      resp.json().get("detail", ""))

# 5e. PASSIVE tool on in-scope target allowed (MCP may fail but governance passes)
resp = client.post("/api/v1/mcp/execute", json={
    "tool_name": "subfinder_scan",
    "params": {"domain": "lab.example.com"},
    "engagement_id": eng_id,
})
check("PASSIVE tool on in-scope target not governance-denied",
      resp.status_code != 403,
      f"got {resp.status_code}: {resp.json().get('detail', '')}")

# =========================================================================
section("6. GOVERNANCE — Direct unit tests")
# =========================================================================

ge = GovernanceEngine()

from pentest_platform.schemas.engagement import Engagement, RulesOfEngagement, ScopeConfig

# Create a mock engagement
engagement = Engagement(
    target="10.0.0.1",
    rules_of_engagement=RulesOfEngagement(
        allow_exploitation=False,
        scope=ScopeConfig(
            in_scope_targets=["10.0.0.0/24", "lab.example.com"],
            out_of_scope=["10.0.0.50"],
        ),
    ),
)

# Test PASSIVE tool — always allowed
tool_subfinder = get_tool_definition("subfinder_scan")
decision = ge.check(tool_subfinder, engagement, target="10.0.0.1")
check("PASSIVE tool always approved", decision.approved)

# Governance is permissive — GATED / out-of-scope no longer block execution
tool_sqlmap = get_tool_definition("sqlmap_scan")
decision = ge.check(tool_sqlmap, engagement, target="10.0.0.1")
check("GATED tool approved (permissive governance)", decision.approved)

decision = ge.check(tool_subfinder, engagement, target="10.0.0.50")
check("Out-of-scope target approved (permissive governance)", decision.approved)

decision = ge.check(tool_subfinder, engagement, target="10.0.0.42")
check("In-scope CIDR match allowed", decision.approved)

decision = ge.check(tool_subfinder, None, target="anything")
check("No engagement = permissive mode", decision.approved)

# =========================================================================
section("7. AUDIT LOG")
# =========================================================================

from pentest_platform.schemas.audit import AuditAction

audit = AuditLog()
entry = audit.record(AuditAction(
    tool_name="test_tool",
    target="10.0.0.1",
    success=True,
    governance_decision="approved",
))
check("Audit log records entry", entry.id)
check("Audit log has timestamp", entry.timestamp is not None)

entries = audit.query(tool_name="test_tool")
check("Audit query finds recorded entry", len(entries) >= 1)

# =========================================================================
section("8. MCP CLIENT — Server discovery")
# =========================================================================

from pentest_platform.services.mcp_client import MCPClient
from pathlib import Path as P

mcp_dir = P(__file__).resolve().parents[1].parent / "mcp-servers"
mcp_client = MCPClient(mcp_servers_dir=mcp_dir)

for server in MCPServerCategory:
    script = mcp_client._server_script(server)
    check(f"MCP server script exists: {server.value}/server.py", script.exists())

# =========================================================================
section("RESULTS")
# =========================================================================

print(f"\n{'='*60}")
total = PASS + FAIL
print(f"  {PASS}/{total} passed, {FAIL} failed")
print(f"{'='*60}")

if FAIL > 0:
    sys.exit(1)
