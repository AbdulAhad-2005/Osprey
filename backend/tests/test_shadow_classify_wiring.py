"""Component 1 end-to-end glue: _shadow_classify_and_observe wired into
tool_execution.py, tested directly against constructed ToolExecutionResponse
objects — same convention other tests in this suite use to avoid needing a
live Kali/MCP connection for unit coverage.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.tools import ToolExecutionResponse
from pentest_platform.services.recovery_observation_store import get_recovery_observation_store
from pentest_platform.services.tool_execution import _shadow_classify_and_observe


def _make_engagement(client: TestClient, target: str) -> str:
    resp = client.post("/api/v1/engagements/", json={"target": target, "name": "shadow-wiring-test"})
    return resp.json()["id"]


def test_shadow_wiring_records_an_observation_for_a_classified_failure() -> None:
    with TestClient(app) as client:
        eid = _make_engagement(client, "shadowwire1.test")
        response = ToolExecutionResponse(
            tool_name="nmap_service_scan",
            success=False,
            returncode=124,
            stdout="",
            stderr="Operation timed out after 90s",
        )
        _shadow_classify_and_observe(
            response,
            engagement_id=eid,
            run_id="",
            tool_name="nmap_service_scan",
            asset="shadowwire1.test",
            empty_success=False,
        )
        rows = get_recovery_observation_store().list_for_engagement(eid)
        assert len(rows) == 1
        assert rows[0].error_type == "timeout"
        assert rows[0].shadow_strategy == "retry_with_backoff"


def test_shadow_wiring_records_nothing_for_a_genuine_success() -> None:
    with TestClient(app) as client:
        eid = _make_engagement(client, "shadowwire2.test")
        response = ToolExecutionResponse(
            tool_name="naabu_port_scan",
            success=True,
            returncode=0,
            stdout="22/tcp open\n80/tcp open\nconnection refused on 21/tcp\n",
            stderr="",
        )
        _shadow_classify_and_observe(
            response,
            engagement_id=eid,
            run_id="",
            tool_name="naabu_port_scan",
            asset="shadowwire2.test",
            empty_success=False,
        )
        # "connection refused" appears in successful output — must NOT be
        # misclassified as a failure just because the exit was zero.
        assert get_recovery_observation_store().list_for_engagement(eid) == []


def test_shadow_wiring_never_raises_on_missing_engagement_id() -> None:
    # Defensive contract: must be safe to call even when engagement_id is
    # empty (e.g. a call that failed before session resolution) — never break
    # the real response it's piggybacking on.
    response = ToolExecutionResponse(tool_name="whois_lookup", success=False, returncode=1, stderr="boom")
    _shadow_classify_and_observe(
        response, engagement_id="", run_id="", tool_name="whois_lookup", asset="", empty_success=False
    )
