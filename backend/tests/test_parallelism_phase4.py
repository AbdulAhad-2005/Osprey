"""Phase 4: parallelism config — soft jobs visibility, no auto-start."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pentest_platform.main import app
from pentest_platform.schemas.finding import Finding, FindingType
from pentest_platform.schemas.tools import ToolExecutionResponse
from pentest_platform.services.findings_store import get_findings_store
from pentest_platform.services.open_loops import build_open_loops
from pentest_platform.services.parallelism_config import (
    jobs_header_line,
    max_running_jobs,
    parallel_soft_note,
    reload_parallelism,
    suggest_background,
)
from pentest_platform.services.tool_execution import _attach_parallel_note


def test_parallelism_config_loads() -> None:
    reload_parallelism()
    assert max_running_jobs() >= 1
    assert suggest_background("amass_scan", 60) is True
    assert suggest_background("unknown_tiny_tool", 30) is False
    assert suggest_background("unknown_tiny_tool", 180) is True
    note = parallel_soft_note("amass_scan", 300)
    assert "job_start" in note.lower() or "parallel" in note.lower()
    assert "optional" in note.lower() or "your call" in note.lower()
    # Never imperative must-run language
    assert "must " not in note.lower()


def test_jobs_header_line_format() -> None:
    reload_parallelism()
    line = jobs_header_line(
        [
            {"status": "running", "label": "amass_scan"},
            {"status": "queued", "tool_name": "nmap_syn_scan"},
            {"status": "completed", "label": "old"},
        ]
    )
    assert line.startswith("jobs:")
    assert "/4" in line or f"/{max_running_jobs()}" in line
    assert "amass" in line.lower() or "nmap" in line.lower()


def test_batch_probe_gap_not_tool_order() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "batch-p4.test", "name": "p4-batch"},
        ).json()
    eid = eng["id"]
    store = get_findings_store()
    for i in range(12):
        store.add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.URL,
                title=f"https://h{i}.batch-p4.test/",
                source_tool="httpx_probe",
            )
        )
        store.add(
            Finding(
                engagement_id=eid,
                finding_type=FindingType.SUBDOMAIN,
                title=f"h{i}.batch-p4.test",
                source_tool="subfinder_scan",
            )
        )
    packet = build_open_loops(eid, max_loops=10)
    ids = {loop["id"] for loop in packet["loops"]}
    assert "batch_probe_pending" in ids
    text = packet["text"].lower()
    assert "must fanout" not in text
    assert "try:" not in text
    batch = next(l for l in packet["loops"] if l["id"] == "batch_probe_pending")
    assert "gap" in batch
    assert "try" not in batch


def test_parallel_note_on_response_soft() -> None:
    resp = ToolExecutionResponse(
        tool_name="amass_scan",
        success=True,
        command="amass",
        returncode=0,
        stdout="ok",
    )
    _attach_parallel_note(resp, tool_name="amass_scan", timeout=300)
    assert isinstance(resp.hybrid, dict)
    assert "parallel_note" in resp.hybrid
    assert "optional" in resp.hybrid["parallel_note"].lower() or "your call" in resp.hybrid[
        "parallel_note"
    ].lower()


def test_context_includes_jobs_line() -> None:
    with TestClient(app) as client:
        eng = client.post(
            "/api/v1/engagements/",
            json={"target": "jobsline-p4.test"},
        ).json()
        eid = eng["id"]
        ctx = client.get(
            "/api/v1/hybrid/context/auto",
            params={"engagement_id": eid},
        ).json()
        assert "jobs_line" in ctx
        assert str(ctx["jobs_line"]).startswith("jobs:")
