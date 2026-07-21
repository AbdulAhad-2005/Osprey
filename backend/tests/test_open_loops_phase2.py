"""Phase 2: open gaps are data — no tool orders in loop text."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.open_loops import build_open_loops
from pentest_platform.services.tool_execution import _attach_recovery_hints
from pentest_platform.schemas.tools import ToolExecutionResponse


def test_open_loops_use_gap_not_try() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "gapcorp.test", "name": "p2-gaps"},
        ).json()
    eid = eng["id"]
    # Enough hosts without HTTP → hosts_no_http gap
    store = get_findings_store()
    for i in range(6):
        store.add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.SUBDOMAIN,
                title=f"h{i}.gapcorp.test",
                source_tool="subfinder_scan",
            )
        )
    packet = build_open_loops(eid, max_loops=8)
    assert packet["count"] >= 1
    text = packet["text"]
    assert "try:" not in text.lower()
    assert "nmap" not in text.lower()
    assert "gap:" in text.lower() or "gap:" in str(packet["loops"]).lower()
    for loop in packet["loops"]:
        assert "gap" in loop
        assert "try" not in loop
        assert "why" in loop


def test_recovery_hint_no_try_next_orders() -> None:
    resp = ToolExecutionResponse(
        tool_name="subfinder_scan",
        success=False,
        command="subfinder",
        returncode=1,
        error="boom",
        alternative_tool_suggested="amass_scan",
    )
    _attach_recovery_hints(resp, empty_success=False)
    assert "TRY NEXT" not in (resp.next_hint or "")
    assert "FALLBACK TOOLS" not in (resp.next_hint or "")
    assert "Gap:" in (resp.next_hint or "") or "gap" in (resp.next_hint or "").lower()
    # Internal list may still exist for audit — not shown as orders in hint text
    assert resp.fallback_tools  # still populated for recovery_bridge


def test_open_loops_api() -> None:
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": "api-gap.test"}).json()
        eid = eng["id"]
        data = client.get(
            "/api/v1/hybrid/open-loops",
            params={"engagement_id": eid},
        ).json()
        assert "loops" in data
        assert "note" in data
        assert "stage script" in (data.get("note") or "").lower() or "choose" in (
            data.get("note") or ""
        ).lower()
