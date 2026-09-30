"""Every tool call must publish tool_start/tool_end onto the shared event bus
from inside execute_tool_request itself — the one execution kernel every
path shares (MCP calls, the CLI's free-LLM loop, the deterministic
--engine/--supervised investigation drivers, background jobs). This is the
root-cause wiring the live dashboard depends on: before this, only
kind=AGENT jobs published anything, so a plain tool call was invisible to
any event_bus subscriber.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from osprey.schemas.tools import ToolExecutionRequest, ToolExecutionResponse
from osprey.services import event_bus, tool_execution


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_successful_call_publishes_start_and_end_with_raw_output():
    eid = _make_engagement("dashboard-events-ok.test")
    mcp_call = AsyncMock(return_value=ToolExecutionResponse(
        tool_name="httpx_probe", success=True, stdout="[200] https://dashboard-events-ok.test",
    ))

    with patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()):
        asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="httpx_probe",
            params={"target": "dashboard-events-ok.test"},
            engagement_id=eid,
            record_findings=True,
            use_cache=False,
        )))

    records = event_bus.history(eid, limit=50)
    events = [r["event"] for r in records]
    assert "tool_start" in events
    assert "tool_end" in events

    start = next(r for r in records if r["event"] == "tool_start")
    assert start["data"]["tool_name"] == "httpx_probe"
    assert start["source"] == "tool"

    end = next(r for r in records if r["event"] == "tool_end")
    assert end["data"]["tool_name"] == "httpx_probe"
    assert end["data"]["success"] is True
    assert "dashboard-events-ok.test" in end["data"]["stdout"]


def test_failed_call_still_publishes_tool_end_with_success_false():
    eid = _make_engagement("dashboard-events-fail.test")
    mcp_call = AsyncMock(return_value=ToolExecutionResponse(
        tool_name="httpx_probe", success=False, stdout="", error="connection refused",
    ))

    with patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()):
        asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="httpx_probe",
            params={"target": "dashboard-events-fail.test"},
            engagement_id=eid,
            record_findings=True,
            use_cache=False,
        )))

    records = event_bus.history(eid, limit=50)
    end = next(r for r in records if r["event"] == "tool_end")
    assert end["data"]["success"] is False
    assert end["data"]["error"] == "connection refused"
