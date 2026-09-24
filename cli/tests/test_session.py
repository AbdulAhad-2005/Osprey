from __future__ import annotations

from cli.session import ToolTranscript


def test_transcript_matches_tool_end_by_tool_call_id() -> None:
    transcript = ToolTranscript()

    first = transcript.start(
        {
            "tool_name": "httpx_probe",
            "arguments": {"target": "example.com"},
            "tool_call_id": "call_1",
            "phase": "recon",
        }
    )
    second = transcript.start(
        {
            "tool_name": "httpx_probe",
            "arguments": {"target": "www.example.com"},
            "tool_call_id": "call_2",
            "phase": "recon",
        }
    )

    done = transcript.end(
        {
            "tool_name": "httpx_probe",
            "tool_call_id": "call_1",
            "success": True,
            "duration_seconds": 1.25,
            "command": "httpx -u example.com",
            "artifacts": {"stdout_path": "/tmp/pentest/e/httpx.stdout.txt"},
            "finding_titles": ["live host"],
        }
    )

    assert done.id == first.id
    assert transcript.get(first.id).status_text == "ok"
    assert transcript.get(first.id).stdout_path.endswith("httpx.stdout.txt")
    assert transcript.get(second.id).status_text == "running"


def test_transcript_can_fall_back_to_tool_name_and_source() -> None:
    transcript = ToolTranscript()
    started = transcript.start(
        {"tool_name": "nmap_service_scan", "arguments": {"target": "1.2.3.4"}},
        source="agent:network",
    )

    done = transcript.end(
        {"tool_name": "nmap_service_scan", "success": False},
        source="agent:network",
    )

    assert done.id == started.id
    assert transcript.get("#1").status_text == "failed"


def test_transcript_deduplicates_replayed_tool_start_events() -> None:
    transcript = ToolTranscript()
    first = transcript.start(
        {
            "tool_name": "subfinder_scan",
            "arguments": {"domain": "example.com"},
            "tool_call_id": "call_replay",
        }
    )

    replayed = transcript.start(
        {
            "tool_name": "subfinder_scan",
            "arguments": {"domain": "example.com"},
            "tool_call_id": "call_replay",
        }
    )

    assert replayed.id == first.id
    assert len(transcript.recent()) == 1
