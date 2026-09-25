"""Tests for _complete_with_feedback — the periodic "still waiting" signal
during a slow/retrying LLM completion.

Confirmed live during QA: a genuinely overloaded provider (complete()'s own
3-attempt x up to 120s retry) can leave the CLI silent for several minutes,
indistinguishable from a hang. These tests verify the wrapper reports elapsed
time on a slow call and stays silent (fast success) on a normal one, without
needing a real LLM call.
"""

from __future__ import annotations

import asyncio

import pytest

from cli.agent import loop as L
from cli.agent.llm import CLIModelConfig


def _run(coro):
    return asyncio.run(coro)


def _config() -> CLIModelConfig:
    return CLIModelConfig(model="test/model", api_key="test-key")


def _runner() -> L.Runner:
    # Bypass __init__'s platform_tools.load_server() — these tests only exercise
    # _complete_with_feedback, which never touches the tool layer.
    runner = L.Runner.__new__(L.Runner)
    runner.config = _config()
    runner.messages = []
    return runner


async def _collect(runner: L.Runner, tool_schemas: list) -> list[L.Event]:
    return [e async for e in runner._complete_with_feedback(tool_schemas)]


def test_fast_success_yields_no_waiting_events(monkeypatch):
    async def _fast_complete(**kwargs):
        return {"choices": [{"message": {"content": "hi"}}]}

    monkeypatch.setattr(L, "complete", _fast_complete)
    monkeypatch.setattr(L, "_STILL_WAITING_INTERVAL", 10.0)
    runner = _runner()

    events = _run(_collect(runner, []))
    assert [e.type for e in events] == ["llm_result"]
    assert events[0].data["response"]["choices"][0]["message"]["content"] == "hi"


def test_slow_call_yields_periodic_waiting_events_then_result(monkeypatch):
    async def _slow_complete(**kwargs):
        await asyncio.sleep(0.09)
        return {"choices": [{"message": {"content": "done"}}]}

    monkeypatch.setattr(L, "complete", _slow_complete)
    monkeypatch.setattr(L, "_STILL_WAITING_INTERVAL", 0.03)  # tiny, for a fast test
    runner = _runner()

    events = _run(_collect(runner, []))
    waiting = [e for e in events if e.type == "llm_still_waiting"]
    result = [e for e in events if e.type == "llm_result"]
    assert len(waiting) >= 1  # at least one interim tick before the 0.09s call finished
    assert waiting == sorted(waiting, key=lambda e: e.data["elapsed_seconds"])  # monotonic
    assert len(result) == 1
    assert result[0].data["response"]["choices"][0]["message"]["content"] == "done"
    assert "error" not in result[0].data


def test_failure_is_reported_as_error_not_raised(monkeypatch):
    async def _failing_complete(**kwargs):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(L, "complete", _failing_complete)
    monkeypatch.setattr(L, "_STILL_WAITING_INTERVAL", 10.0)
    runner = _runner()

    events = _run(_collect(runner, []))
    assert [e.type for e in events] == ["llm_result"]
    assert isinstance(events[0].data["error"], RuntimeError)


def test_cancellation_during_wait_propagates_and_cancels_task(monkeypatch):
    started = asyncio.Event()

    async def _never_completes(**kwargs):
        started.set()
        await asyncio.sleep(3600)

    monkeypatch.setattr(L, "complete", _never_completes)
    monkeypatch.setattr(L, "_STILL_WAITING_INTERVAL", 0.02)
    runner = _runner()

    async def _scenario():
        gen = runner._complete_with_feedback([])

        async def _consume():
            async for _ in gen:
                pass

        task = asyncio.ensure_future(_consume())
        await started.wait()
        await asyncio.sleep(0.05)  # let at least one waiting-tick pass
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    _run(_scenario())
