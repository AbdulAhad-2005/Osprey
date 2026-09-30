"""_maybe_auto_fallback built its retry ToolExecutionRequest with no
``timeout=`` field, so every auto-fallback hop silently reverted to the
schema's generic 900s default regardless of how tight the ORIGINAL caller's
budget was. This reproduced the exact "dnsenum ran for 40 minutes" bug one
level deeper: investigation_capabilities.py gives dnsenum_scan a 60s ceiling,
the first attempt correctly times out fast, but the escalation matrix's own
dnsenum -> subfinder_scan hop (config/escalation_matrix.yaml) then ran with
900s instead of the same 60s ceiling — observed live as a tool card stuck
"running…" on the dashboard long after its opportunity was supposed to be
capped.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from osprey.schemas.tools import ToolExecutionRequest, ToolExecutionResponse
from osprey.services import tool_execution


def _make_engagement(target: str) -> str:
    from fastapi.testclient import TestClient

    from osprey.main import app

    with TestClient(app) as client:
        resp = client.post("/api/v1/engagements/", json={"target": target})
        return resp.json()["id"]


def test_auto_fallback_retry_inherits_the_original_tight_timeout():
    eid = _make_engagement("fallback-timeout.test")

    # First call: dnsenum_scan times out with a thin/empty body — matches the
    # real escalation_matrix.yaml entry that alternates to subfinder_scan on
    # a dnsenum timeout/failure.
    timed_out_response = ToolExecutionResponse(
        tool_name="dnsenum_scan", success=False, stdout="", timed_out=True, error="timed out",
    )
    ok_response = ToolExecutionResponse(
        tool_name="subfinder_scan", success=True, stdout="sub.fallback-timeout.test",
    )
    mcp_call = AsyncMock(side_effect=[timed_out_response, ok_response])

    with patch.object(tool_execution, "get_mcp_client", return_value=type("M", (), {"call_tool": mcp_call})()):
        result = asyncio.run(tool_execution.execute_tool_request(ToolExecutionRequest(
            tool_name="dnsenum_scan",
            params={"domain": "fallback-timeout.test"},
            engagement_id=eid,
            record_findings=True,
            use_cache=False,
            use_recovery=True,
            timeout=60,
        )))

    assert mcp_call.await_count == 2, "expected the original call plus one auto-fallback hop"
    assert result.hybrid.get("auto_fallback"), "expected the auto-fallback metadata to be attached"

    first_call_kwargs = mcp_call.await_args_list[0].kwargs
    second_call_kwargs = mcp_call.await_args_list[1].kwargs
    assert first_call_kwargs["timeout"] == 60
    assert second_call_kwargs["timeout"] == 60, (
        "the auto-fallback retry must inherit the original request's timeout, "
        "not silently fall back to ToolExecutionRequest's generic 900s default"
    )
