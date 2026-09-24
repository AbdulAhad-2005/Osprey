"""Execution errors stay diagnostic; partial target output stays evidence."""

from __future__ import annotations

import asyncio

from osprey.schemas.tools import ToolExecutionResponse
from osprey.services.summary_agent import summarize_execution
from osprey.services.tool_execution import _evidence_streams


def _response(*, success: bool, stdout: str = "", stderr: str = ""):
    return ToolExecutionResponse(
        tool_name="unknown_probe",
        success=success,
        command="unknown_probe example.test",
        returncode=0 if success else 2,
        stdout=stdout,
        stderr=stderr,
        error="execution failed" if not success else "",
    )


def test_failed_stderr_is_not_an_ingest_evidence_stream() -> None:
    response = _response(
        success=False,
        stderr="80/tcp open http\nServer: nginx/1.25",
    )

    assert _evidence_streams(response) == ("", "")


def test_successful_stderr_remains_available_for_tools_that_use_it() -> None:
    response = _response(success=True, stderr="Server: nginx/1.25")

    assert _evidence_streams(response) == ("", "Server: nginx/1.25")


def test_failed_stderr_only_does_not_create_raw_finding() -> None:
    response = _response(
        success=False,
        stderr="connection refused while parsing 443/tcp open https",
    )

    findings = asyncio.run(
        summarize_execution(
            response,
            engagement_id="stderr-test",
            target="example.test",
            force_raw_observation=True,
        )
    )

    assert findings == []


def test_partial_stdout_from_failed_tool_is_preserved() -> None:
    response = _response(
        success=False,
        stdout="probe reached target but timed out during follow-up",
        stderr="fatal worker error",
    )

    findings = asyncio.run(
        summarize_execution(
            response,
            engagement_id="partial-test",
            target="example.test",
            force_raw_observation=True,
        )
    )

    assert len(findings) == 1
    assert findings[0].evidence.startswith("probe reached target")
    assert "partial_failed_output" in findings[0].tags
    assert "fatal worker error" not in findings[0].evidence
