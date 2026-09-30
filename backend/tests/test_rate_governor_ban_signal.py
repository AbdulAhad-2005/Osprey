"""A WAF/rate-limit ban signal detected while pacing our OWN calls describes
Osprey's execution against the target, not a fact about the target's
security posture — it must never enter observation_store/findings_store
(which every downstream consumer — promote_observations, reports, priority
scoring, exploit candidates — treats as claims about the target). It
belongs only on the calling tool's audit-log entry.

Regression coverage for the fix that replaced tool_execution.py's
Observation(type=SCANNER_SIGNAL, source_tool="rate_governor", ...) write
with audit-log metadata.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from osprey.schemas.observation import ObservationType
from osprey.schemas.tools import ToolExecutionRequest, ToolExecutionResponse
from osprey.services import tool_execution
from osprey.services.audit_log import get_audit_log
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_ban_signal_never_becomes_an_observation_or_finding():
    eid = _make_engagement("ban-signal-no-observation.test")
    ban_stdout = "HTTP/1.1 429 Too Many Requests\ncf-ray: abc123-XYZ\nerror code 1015"
    mcp_call = AsyncMock(return_value=ToolExecutionResponse(
        tool_name="httpx_probe", success=True, stdout=ban_stdout,
    ))

    with (
        patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()),
    ):
        result = asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="httpx_probe",
            params={"target": "ban-signal-no-observation.test"},
            engagement_id=eid,
            record_findings=True,
            use_cache=False,
        )))

    assert result.success is True

    observations = get_observation_store().list_by_type(eid, ObservationType.SCANNER_SIGNAL)
    assert all(o.source_tool != "rate_governor" for o in observations)

    findings = get_findings_store().list(engagement_id=eid, limit=200)
    assert all(f.source_tool != "rate_governor" for f in findings)


def test_ban_signal_is_recorded_on_the_audit_log_instead():
    eid = _make_engagement("ban-signal-audit-log.test")
    ban_stdout = "HTTP/1.1 429 Too Many Requests\ncf-ray: abc123-XYZ\nerror code 1015"
    mcp_call = AsyncMock(return_value=ToolExecutionResponse(
        tool_name="httpx_probe", success=True, stdout=ban_stdout,
    ))

    with (
        patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()),
    ):
        asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="httpx_probe",
            params={"target": "ban-signal-audit-log.test"},
            engagement_id=eid,
            record_findings=True,
            use_cache=False,
        )))

    entries = get_audit_log().query(engagement_id=eid, tool_name="httpx_probe")
    assert entries, "expected an audit-log entry for the call"
    assert entries[-1].action.metadata.get("ban_signal"), "ban fingerprint should be on the audit entry's metadata"


def test_clean_output_leaves_ban_signal_metadata_empty():
    eid = _make_engagement("ban-signal-clean.test")
    mcp_call = AsyncMock(return_value=ToolExecutionResponse(
        tool_name="httpx_probe", success=True, stdout="200 OK, nothing suspicious here",
    ))

    with (
        patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()),
    ):
        asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="httpx_probe",
            params={"target": "ban-signal-clean.test"},
            engagement_id=eid,
            record_findings=True,
            use_cache=False,
        )))

    entries = get_audit_log().query(engagement_id=eid, tool_name="httpx_probe")
    assert entries
    assert entries[-1].action.metadata.get("ban_signal") == ""
