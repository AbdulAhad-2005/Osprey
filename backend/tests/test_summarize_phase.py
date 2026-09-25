"""summarize_phase() end-of-phase brief — regression coverage for the LLM-prompt
path, which previously referenced a `reflection` variable removed along with
phase_reflection.py without updating this call site (NameError at runtime,
only reachable when tool_summaries is non-empty — no prior test exercised it).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from osprey.schemas.agent_run import ToolSummary
from osprey.services import summary_agent


def _run(coro):
    return asyncio.run(coro)


def test_summarize_phase_with_tool_summaries_does_not_raise():
    """The LLM-narrative branch (tool_summaries non-empty) must not reference
    anything removed alongside phase_reflection.py."""
    mock_llm = MagicMock()
    mock_llm.complete = AsyncMock(
        return_value={"choices": [{"message": {"content": "narrative text"}}]}
    )
    with patch("osprey.services.summary_agent.export_structured_findings") as mock_export:
        mock_export.return_value = MagicMock(
            findings_by_type={"subdomain": ["a.example.com"]},
            text_summary="some findings",
        )
        brief = _run(
            summary_agent.summarize_phase(
                "recon",
                target="example.com",
                resolved_ip=None,
                tool_summaries=[
                    ToolSummary(tool_name="subfinder_scan", success=True, prose="found stuff")
                ],
                engagement_id="e1",
                run_id="r1",
                llm=mock_llm,
            )
        )
    assert brief.prose_summary == "narrative text"
    assert brief.phase == "recon"


def test_summarize_phase_with_no_tool_summaries_short_circuits():
    with patch("osprey.services.summary_agent.export_structured_findings") as mock_export:
        mock_export.return_value = MagicMock(findings_by_type={}, text_summary="")
        brief = _run(
            summary_agent.summarize_phase(
                "recon",
                target="example.com",
                resolved_ip=None,
                tool_summaries=[],
                engagement_id="e1",
                run_id="r1",
            )
        )
    assert "No tool runs recorded" in brief.prose_summary
