import asyncio

from agent_core import loop
from agent_core.llm import CLIModelConfig


class Gateway:
    engagement_id = "resume-loop"

    def schemas(self, **kwargs):
        return []

    async def call(self, *args):
        return "recorded proof"


def runner_with_responses(responses, max_turns=0):
    runner = loop.Runner(config=CLIModelConfig(model="test/model", api_key="test"),
                         api_base_url="", tool_gateway=Gateway(), max_turns=max_turns)
    async def manage(*args):
        if False:
            yield
    async def complete(*args):
        yield loop.Event("llm_result", {"response": {"choices": [{"message": next(responses)}]}})
    runner._manage_context = manage
    runner._complete_with_feedback = complete
    return runner


def test_interactive_run_can_continue_beyond_thirty_steps():
    responses = iter([{"tool_calls": [{"id": str(i), "function": {"name": "platform_context", "arguments": "{}"}}]}
                      for i in range(31)] + [{"content": "Completed objective"}])
    runner = runner_with_responses(responses)
    async def collect():
        return [event async for event in runner.run("Review saved context")]
    events = asyncio.run(collect())
    assert sum(event.type == "tool_end" for event in events) == 31
    assert events[-1].data["reason"] == "completed"


def test_empty_response_retries_once_then_reports_resumable_error():
    runner = runner_with_responses(iter([{"content": ""}, {"content": None}]))
    async def collect():
        return [event async for event in runner.run("continue")]
    events = asyncio.run(collect())
    assert sum(event.type == "llm_call_start" for event in events) == 2
    assert events[-1].data["reason"] == "empty_response"
    assert any(event.type == "error" for event in events)
    assert not any(message.get("role") == "assistant" for message in runner.messages)


def test_explicit_worker_budget_remains_bounded():
    response = {"tool_calls": [{"id": "call", "function": {"name": "platform_context", "arguments": "{}"}}]}
    runner = runner_with_responses(iter([response]), max_turns=1)
    async def collect():
        return [event async for event in runner.run("bounded work")]
    assert asyncio.run(collect())[-1].data["reason"] == "turn_limit"


def test_local_operator_methodology_is_loaded_from_repo_root():
    from agent_core.context import _load_agents_md
    _load_agents_md.cache_clear()
    assert "Pin every call" in _load_agents_md()


def test_failed_compaction_does_not_discard_original_objective_or_tool_history(monkeypatch):
    from agent_core.compaction import ContextBudget
    runner = runner_with_responses(iter([]))
    original = [{"role": "user", "content": "Original objective"},
                {"role": "assistant", "content": "First result"},
                {"role": "user", "content": "Continue"},
                {"role": "assistant", "content": "Recent result"}]
    runner.messages = list(original)
    runner._budget = ContextBudget(context_limit=10000, reserve=1000, compact_at=100, keep_recent_tokens=1)
    async def empty_summary(**kwargs):
        return {"choices": [{"message": {"content": ""}}]}
    monkeypatch.setattr(loop, "complete", empty_summary)
    assert asyncio.run(runner._compact_now()) is False
    assert runner.messages == original
