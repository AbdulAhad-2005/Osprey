"""
Full integration test script for the tool feature.

Tests the complete pipeline:
  1. Tool catalog (90 tools, categories, safety levels)
  2. Engagement CRUD with scope config
  3. Execution is never policy-gated (ROE/scope are persisted + shown to the agent only)
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
section("5. EXECUTION — no policy gate blocks tool calls")
# =========================================================================

# Create engagement with ROE/scope set (still persisted + shown to the
# agent, but no longer consulted before execution — see docs/ENGINEERING_REFERENCE.md)
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

# Any tool call is attempted regardless of ROE/scope; execution is never
# blocked by a policy layer, so a 403 here would indicate a regression.
resp = client.post("/api/v1/mcp/execute", json={
    "tool_name": "subfinder_scan",
    "params": {"domain": "lab.example.com"},
    "engagement_id": eng_id,
})
check("Tool execution is never policy-denied (no 403)",
      resp.status_code != 403,
      f"got {resp.status_code}: {resp.json().get('detail', '')}")

# =========================================================================
section("7. AUDIT LOG")
# =========================================================================

from pentest_platform.schemas.audit import AuditAction

audit = AuditLog()
entry = audit.record(AuditAction(
    tool_name="test_tool",
    target="10.0.0.1",
    success=True,
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
