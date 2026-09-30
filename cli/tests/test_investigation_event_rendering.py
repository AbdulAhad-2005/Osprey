"""_run_investigation_events must render exactly like the free-LLM loop and
background pipeline events — through the same ToolTranscript-backed
print_tool_start_live/print_tool_end_live, not a second, cruder rendering
system. This is the actual fix for "doesn't feel like Claude Code": before,
the deterministic/supervised engine printed plain scrollback lines with no
tool-call cards, no #id, no duration, no /tool N reference.
"""

from __future__ import annotations

from cli.commands.scan_shared import _run_investigation_events
from cli.harness.drivers import JobEvent
from cli.session import ToolTranscript


class _FakeClient:
    pass


def test_decision_and_completion_render_as_one_tool_call_card():
    transcript = ToolTranscript()
    events = [
        JobEvent("state", {"state_summary": "17 opportunities ready."}),
        JobEvent("decision", {
            "opportunity_id": "opp-1", "capability": "discover_related_domains",
            "label": "samaa.tv", "priority": 110, "rationale": "not yet run",
            "driver": "deterministic", "tool": "crt_sh_query", "params": {"domain": "samaa.tv"},
        }),
        JobEvent("capability_started", {"job_id": "job-1", "opportunity_id": "opp-1", "capability": "discover_related_domains"}),
        JobEvent("capability_completed", {
            "job_id": "job-1",
            "result": {"result": {"details": {"results": [
                {"tool": "crt_sh_query", "success": True, "finding_titles": ["sub.samaa.tv"], "error": ""}
            ]}}},
        }),
        JobEvent("complete", {"state_summary": "Surface exhausted."}),
    ]

    result = _run_investigation_events(_FakeClient(), events, transcript=transcript, source="engine")

    assert result is True
    records = transcript.recent()
    assert len(records) == 1
    rec = records[0]
    assert rec.tool_name == "crt_sh_query"
    assert rec.source == "engine"
    assert rec.success is True
    assert rec.finding_titles == ["sub.samaa.tv"]
    assert rec.arguments == {"domain": "samaa.tv"}


def test_failed_tool_call_is_recorded_as_failed():
    transcript = ToolTranscript()
    events = [
        JobEvent("decision", {
            "opportunity_id": "opp-2", "capability": "enumerate_subdomains",
            "tool": "dnsenum_scan", "params": {"domain": "samaa.tv"},
        }),
        JobEvent("capability_completed", {
            "job_id": "job-2",
            "result": {"result": {"details": {"results": [
                {"tool": "dnsenum_scan", "success": False, "finding_titles": [], "error": "timed out"}
            ]}}},
        }),
    ]

    _run_investigation_events(_FakeClient(), events, transcript=transcript, source="engine")

    rec = transcript.recent()[0]
    assert rec.success is False
    assert rec.status_text == "failed"


def test_analytical_opportunity_with_no_tool_does_not_create_a_tool_card():
    """promote_observations/detect_anomalies/etc. are real actions but not
    Kali tool calls — they must not be rendered as a fake tool-call card."""
    transcript = ToolTranscript()
    events = [
        JobEvent("decision", {
            "opportunity_id": "opp-3", "capability": "detect_anomalies",
            "label": "peer-diff refresh", "rationale": "world-state changed", "tool": "", "params": {},
        }),
        JobEvent("capability_completed", {
            "job_id": "job-3",
            "result": {"result": {"details": {"results": [{"anomalies": 2}]}}},
        }),
        JobEvent("complete", {"state_summary": "done"}),
    ]

    _run_investigation_events(_FakeClient(), events, transcript=transcript, source="engine")

    assert transcript.recent() == []


def test_resumed_reattach_uses_the_real_tool_name():
    transcript = ToolTranscript()
    events = [
        JobEvent("capability_started", {"job_id": "job-4", "resumed": True, "tool": "amass_scan"}),
        JobEvent("capability_completed", {
            "job_id": "job-4",
            "result": {"result": {"details": {"results": [{"tool": "amass_scan", "success": True}]}}},
        }),
        JobEvent("complete", {"state_summary": "done"}),
    ]

    _run_investigation_events(_FakeClient(), events, transcript=transcript, source="engine")

    rec = transcript.recent()[0]
    assert rec.tool_name == "amass_scan"


def test_checkpoint_tool_calls_render_through_the_same_system_tagged_checkpoint():
    """A supervised-mode checkpoint hands the LLM the full unrestricted
    ReAct loop — its tool calls must render exactly like any other tool
    call, just tagged [checkpoint], not a third bespoke format."""
    transcript = ToolTranscript()
    events = [
        JobEvent("checkpoint_started", {"reason": "10 opportunities completed"}),
        JobEvent("checkpoint_llm_event", {
            "type": "tool_start",
            "data": {"tool_name": "nuclei_scan", "arguments": '{"target": "samaa.tv"}', "tool_call_id": "tc-1"},
        }),
        JobEvent("checkpoint_llm_event", {
            "type": "tool_end",
            "data": {"tool_name": "nuclei_scan", "result": "success: true\nfound 1 template match", "tool_call_id": "tc-1"},
        }),
        JobEvent("checkpoint_llm_event", {"type": "done", "data": {"content": "Nothing critical found."}}),
        JobEvent("checkpoint_completed", {"reason": "10 opportunities completed"}),
        JobEvent("complete", {"state_summary": "done"}),
    ]

    _run_investigation_events(_FakeClient(), events, transcript=transcript, source="engine")

    records = transcript.recent()
    assert len(records) == 1
    assert records[0].tool_name == "nuclei_scan"
    assert records[0].source == "checkpoint"
    assert records[0].success is True


def test_engine_and_supervised_sources_are_visually_distinguishable_by_tag():
    for source in ("engine", "supervised"):
        transcript = ToolTranscript()
        events = [
            JobEvent("decision", {"tool": "httpx_probe", "params": {"target": "samaa.tv"}}),
            JobEvent("capability_completed", {
                "result": {"result": {"details": {"results": [{"tool": "httpx_probe", "success": True}]}}},
            }),
        ]
        _run_investigation_events(_FakeClient(), events, transcript=transcript, source=source)
        assert transcript.recent()[0].source == source
