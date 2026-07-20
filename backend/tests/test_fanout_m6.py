"""M6: explicit sister fan-out (dry_run by default, confirm required)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.fanout import FanoutSisterRequest
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.schemas.tools import ToolExecutionResponse
from pentest_platform.services.engagement_graph import get_engagement_graph
from pentest_platform.services.fanout import enumerate_pending_sisters
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.tool_coverage_store import get_tool_coverage_store


def _engagement_with_sister(domain: str = "fanout-seed.test", sister: str = "pending-sis.test"):
    with TestClient(app) as client:
        eng = client.post("/api/v1/engagements/", json={"target": domain}).json()
    eid = eng["id"]
    f = Finding(
        engagement_id=eid,
        finding_type=FindingType.HOST,
        title=sister,
        source_tool="domain_hunter",
        target=domain,
        tags=["sister_domain"],
        metadata={"role": "sister_domain"},
    )
    get_findings_store().add(f)
    get_engagement_graph().ingest_finding(f)
    return eid, sister


def test_fanout_dry_run_default_does_not_execute() -> None:
    eid, sister = _engagement_with_sister()
    # Sync wrapper via TestClient for API default body
    with TestClient(app) as client:
        resp = client.post(f"/api/v1/engagements/{eid}/actions/enumerate-pending-sisters")
        assert resp.status_code == 200
        body = resp.json()
        assert body["dry_run"] is True
        assert body["executed"] is False
        assert body["domains_planned"] >= 1
        assert any(r["domain"] == sister for r in body["results"])
        assert all(r["executed"] is False for r in body["results"])


def test_fanout_without_confirm_stays_preview() -> None:
    eid, sister = _engagement_with_sister("fanout2.test", "sis2.test")
    result = __import__("asyncio").run(
        enumerate_pending_sisters(eid, FanoutSisterRequest(dry_run=False, confirm=False))
    )
    assert result.dry_run is True
    assert result.executed is False
    assert any(r.domain == sister and not r.executed for r in result.results)


def test_fanout_rejects_httpx_tool() -> None:
    eid, _ = _engagement_with_sister("fanout3.test", "sis3.test")
    try:
        __import__("asyncio").run(
            enumerate_pending_sisters(
                eid,
                FanoutSisterRequest(tool_name="httpx_probe", dry_run=True),
            )
        )
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "httpx" not in str(exc).lower() or "must be one of" in str(exc)
        assert "must be one of" in str(exc)


def test_fanout_skips_already_marked_and_executes_with_confirm() -> None:
    eid, sister = _engagement_with_sister("fanout4.test", "sis4.test")
    other = "sis4b.test"
    f = Finding(
        engagement_id=eid,
        finding_type=FindingType.HOST,
        title=other,
        source_tool="domain_hunter",
        target="fanout4.test",
        tags=["sister_domain"],
        metadata={"role": "sister_domain"},
    )
    get_findings_store().add(f)
    get_engagement_graph().ingest_finding(f)

    get_tool_coverage_store().record(
        engagement_id=eid,
        tool_name="subfinder_scan",
        asset=sister,
        findings_count=0,
    )

    mock_resp = ToolExecutionResponse(
        tool_name="subfinder_scan",
        success=True,
        command="subfinder -d sis4b.test",
        finding_titles=[f"a.{other}"],
    )

    with patch(
        "pentest_platform.services.fanout.execute_tool_request",
        new=AsyncMock(return_value=mock_resp),
    ) as mocked:
        result = __import__("asyncio").run(
            enumerate_pending_sisters(
                eid,
                FanoutSisterRequest(
                    dry_run=False,
                    confirm=True,
                    skip_already_marked=True,
                    max_domains=10,
                ),
            )
        )
        assert result.executed is True
        skipped = [r for r in result.results if r.skipped]
        assert any(r.domain == sister for r in skipped)
        executed = [r for r in result.results if r.executed]
        assert any(r.domain == other and r.success for r in executed)
        assert mocked.await_count >= 1
        # Must never call for already-marked sister
        for call in mocked.await_args_list:
            req = call.args[0]
            assert req.params.get("domain") != sister
