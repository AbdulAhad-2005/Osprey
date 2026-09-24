"""Unit tests for the CLI context-management logic (cli/agent/compaction.py).

Pure-function coverage — no live model needed. The token counter and model-info
lookups degrade to safe fallbacks when litellm can't tokenize / doesn't know the
model, so these run offline.
"""

from __future__ import annotations

from cli.agent import compaction as c


def test_spill_leaves_small_results_untouched():
    small = "x" * 100
    assert c.spill_tool_result(small) == small


def test_spill_trims_large_results_with_pointer():
    big = "HEAD" + ("y" * 20_000) + "TAIL"
    out = c.spill_tool_result(big, engagement_id="e1", max_chars=6_000)
    assert out.startswith("HEAD")
    assert out.endswith("TAIL")
    assert len(out) < len(big)
    # Non-destructive: tells the model output was trimmed and where the full copy is.
    assert "trimmed to protect context" in out
    assert "platform_artifact" in out
    assert "e1" in out


def test_split_into_turns_keeps_tool_results_with_their_assistant():
    rest = [
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1", "tool_calls": [{"id": "1", "function": {"name": "t", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "1", "content": "r1"},
        {"role": "user", "content": "u2"},
        {"role": "assistant", "content": "a2"},
    ]
    turns = c.split_into_turns(rest)
    assert len(turns) == 2
    # A tool-call/result pair must never be split across the boundary.
    assert [m["role"] for m in turns[0]] == ["user", "assistant", "tool"]
    assert turns[1][0]["content"] == "u2"


def test_build_budget_fallback_for_unknown_model():
    b = c.build_budget("totally-unknown-model-xyz", requested_max_tokens=4096, tpm_budget_tokens=0)
    assert b.context_limit > 0
    assert 0 < b.compact_at < b.usable
    assert b.keep_recent_tokens >= 2_000


def test_tpm_budget_lowers_effective_window():
    b = c.build_budget("totally-unknown-model-xyz", requested_max_tokens=4096, tpm_budget_tokens=8_000)
    assert b.context_limit == 8_000


def test_plan_compaction_preserves_system_and_cuts_on_turn_boundary():
    msgs = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1", "tool_calls": [{"id": "1", "function": {"name": "t", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "1", "content": "r1"},
        {"role": "user", "content": "u2"},
        {"role": "assistant", "content": "a2"},
    ]
    budget = c.ContextBudget(context_limit=100_000, reserve=5_000, compact_at=100, keep_recent_tokens=10)
    plan = c.plan_compaction("totally-unknown-model-xyz", msgs, budget)
    assert plan.system == [{"role": "system", "content": "s"}]
    assert plan.has_head
    assert plan.tail  # something kept
    # The verbatim tail must start cleanly at a user turn boundary.
    assert plan.tail[0]["role"] == "user"


def test_plan_compaction_noop_when_single_turn():
    msgs = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1"},
    ]
    budget = c.ContextBudget(context_limit=100_000, reserve=5_000, compact_at=100, keep_recent_tokens=10)
    plan = c.plan_compaction("m", msgs, budget)
    assert not plan.has_head  # nothing old enough to summarize


def test_summary_request_and_checkpoint_framing():
    head = [{"role": "user", "content": "u1"}, {"role": "assistant", "content": "a1"}]
    req = c.build_summary_request(head, previous_summary="prev-checkpoint")
    assert req[0]["role"] == "system"
    assert "prev-checkpoint" in req[1]["content"]
    cp = c.checkpoint_message("THE SUMMARY")
    assert cp["role"] == "user"
    assert "THE SUMMARY" in cp["content"]
