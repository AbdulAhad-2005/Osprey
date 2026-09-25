"""GATED tools must be blocked server-side unless the engagement's
RulesOfEngagement actually authorizes them — this was previously a label
only (safety_level=GATED was never read by tool_execution.py), so these
tests pin down the real enforcement added in execute_tool_request.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from osprey.main import app
from osprey.schemas.tools import ToolExecutionRequest
from osprey.services.tool_execution import execute_tool_request


def _make_engagement(target: str, *, allow_exploitation: bool, destructive_actions_allowed: bool = False) -> str:
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/engagements/",
            json={
                "target": target,
                "rules_of_engagement": {
                    "allow_exploitation": allow_exploitation,
                    "destructive_actions_allowed": destructive_actions_allowed,
                },
            },
        )
        return resp.json()["id"]


def test_gated_tool_blocked_without_allow_exploitation():
    eid = _make_engagement("roe-block.test", allow_exploitation=False)
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(execute_tool_request(ToolExecutionRequest(
            tool_name="hydra_attack",
            params={"target": "roe-block.test", "service": "ssh"},
            engagement_id=eid,
        )))
    assert exc_info.value.status_code == 403
    assert "allow_exploitation" in exc_info.value.detail


def test_gated_tool_allowed_with_poc_blast_radius_when_authorized():
    eid = _make_engagement("roe-allow.test", allow_exploitation=True, destructive_actions_allowed=False)
    # hydra_attack will still fail at actual execution (no live target/binary in test env),
    # but it must get PAST the RoE gate, not be blocked by it — assert the failure isn't 403/RoE.
    try:
        asyncio.run(execute_tool_request(ToolExecutionRequest(
            tool_name="hydra_attack",
            params={"target": "roe-allow.test", "service": "ssh"},
            engagement_id=eid,
            blast_radius="poc",
        )))
    except HTTPException as exc:
        assert exc.status_code != 403 or "allow_exploitation" not in (exc.detail or "")


def test_destructive_blast_radius_blocked_without_destructive_actions_allowed():
    eid = _make_engagement("roe-destructive-block.test", allow_exploitation=True, destructive_actions_allowed=False)
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(execute_tool_request(ToolExecutionRequest(
            tool_name="hydra_attack",
            params={"target": "roe-destructive-block.test", "service": "ssh"},
            engagement_id=eid,
            blast_radius="destructive",
        )))
    assert exc_info.value.status_code == 403
    assert "destructive_actions_allowed" in exc_info.value.detail


def test_destructive_blast_radius_allowed_when_authorized():
    eid = _make_engagement("roe-destructive-allow.test", allow_exploitation=True, destructive_actions_allowed=True)
    try:
        asyncio.run(execute_tool_request(ToolExecutionRequest(
            tool_name="hydra_attack",
            params={"target": "roe-destructive-allow.test", "service": "ssh"},
            engagement_id=eid,
            blast_radius="destructive",
        )))
    except HTTPException as exc:
        assert exc.status_code != 403 or "RulesOfEngagement" not in (exc.detail or "")


def test_non_gated_tool_unaffected_by_roe():
    eid = _make_engagement("roe-nongated.test", allow_exploitation=False)
    # subfinder_scan is PASSIVE, not GATED — must never be blocked by exploitation RoE.
    try:
        asyncio.run(execute_tool_request(ToolExecutionRequest(
            tool_name="subfinder_scan",
            params={"domain": "roe-nongated.test"},
            engagement_id=eid,
        )))
    except HTTPException as exc:
        assert exc.status_code != 403 or "allow_exploitation" not in (exc.detail or "")
