"""plans/harness/07-context-packet.md Step 2/4: the system prompt (and the
context packet inside it) must be rebuilt every turn, including across
compaction — never frozen at whatever it was on turn 1. Pure-function unit
tests for the two small helpers that fix this, no LLM/network needed.
"""

from __future__ import annotations

from cli.agent.context import summarize_last_action
from cli.agent.loop import refresh_system_message


def test_inserts_system_message_when_none_exists():
    messages = [{"role": "user", "content": "scan example.com"}]
    result = refresh_system_message(messages, "PACKET v1")
    assert result[0] == {"role": "system", "content": "PACKET v1"}
    assert result[1]["role"] == "user"


def test_replaces_stale_system_message_with_fresh_one():
    """The actual bug this plan fixes: turn 1's packet must not survive
    unchanged into turn 2 once new state exists."""
    messages = [
        {"role": "system", "content": "PACKET v1 (stale — no port 8080 yet)"},
        {"role": "user", "content": "scan example.com"},
        {"role": "assistant", "content": "found port 8080 running Jenkins"},
    ]
    refresh_system_message(messages, "PACKET v2 (fresh — Jenkins on 8080)")
    assert messages[0]["content"] == "PACKET v2 (fresh — Jenkins on 8080)"
    assert len(messages) == 3, "must replace in place, never duplicate the system message"


def test_empty_system_prompt_is_a_noop():
    messages = [{"role": "system", "content": "PACKET v1"}, {"role": "user", "content": "hi"}]
    refresh_system_message(messages, "")
    assert messages[0]["content"] == "PACKET v1"


def test_survives_compaction_shaped_message_lists():
    """After compaction, messages = [system, checkpoint, ...tail] — refresh
    must still target index 0, not get confused by the checkpoint message."""
    messages = [
        {"role": "system", "content": "PACKET v1"},
        {"role": "user", "content": "[Earlier turns summarized]: did recon on example.com"},
        {"role": "user", "content": "keep going"},
    ]
    refresh_system_message(messages, "PACKET v2 (post-compaction, still fresh)")
    assert messages[0] == {"role": "system", "content": "PACKET v2 (post-compaction, still fresh)"}
    assert len(messages) == 3


def test_summarize_last_action_reports_tool_calls():
    messages = [
        {"role": "user", "content": "scan it"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"function": {"name": "nmap_service_scan", "arguments": "{}"}},
            {"function": {"name": "httpx_probe", "arguments": "{}"}},
        ]},
    ]
    assert "nmap_service_scan" in summarize_last_action(messages)
    assert "httpx_probe" in summarize_last_action(messages)


def test_summarize_last_action_reports_final_text_when_no_tool_calls():
    messages = [
        {"role": "user", "content": "scan it"},
        {"role": "assistant", "content": "Recon complete, no live hosts found."},
    ]
    assert "Recon complete" in summarize_last_action(messages)


def test_summarize_last_action_empty_history():
    assert summarize_last_action([]) == "(start of session)"
