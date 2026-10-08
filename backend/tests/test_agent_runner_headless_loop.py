"""agent_runner.run_scoped_agent drives cli.agent.loop.Runner headlessly and
translates its Event stream into the on_event vocabulary job_store.py already
consumes (tool_start/tool_end/assistant/phase_done/error/done) — this is the
one reasoning-loop implementation (no more backend-native PhaseAgent), so the
translation itself is what this file actually needs covering, not the loop's
own internals (covered by cli/tests/test_loop_guards.py etc.) or the LLM
network call (never exercised here).
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import patch

import pytest

# Backend depends on the sibling cli package at runtime; skip cleanly if its
# deps aren't installed in a backend-only venv (conftest puts repo root on path).
Event = pytest.importorskip("cli.agent.loop").Event
from osprey.core.config import LLMSettings

_CONFIGURED = LLMSettings(model="groq/compound-mini", api_key="sk-test-key")


def _eid() -> str:
    return f"e-{uuid.uuid4().hex[:10]}"


class _FakeRunner:
    """Stands in for cli.agent.loop.Runner: records what it was given, yields
    a scripted event sequence from .run() with no LLM/HTTP call."""

    instances: list["_FakeRunner"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.run_calls: list[tuple[str, str]] = []
        _FakeRunner.instances.append(self)

    async def run(self, prompt, *, system_prompt=""):
        self.run_calls.append((prompt, system_prompt))
        yield Event("llm_call_start", {})
        yield Event("tool_start", {"tool_name": "subfinder_scan", "tool_call_id": "c1"})
        yield Event(
            "tool_end",
            {"tool_name": "subfinder_scan", "result": "found 3 subdomains", "success": True,
             "duration_seconds": 1.5, "tool_call_id": "c1"},
        )
        yield Event("thinking", {"content": "moving to httpx next"})
        yield Event("assistant_text", {"content": "Found 3 subdomains, probing them now."})
        yield Event("done", {"content": "Found 3 subdomains, probing them now."})


def _run(role: str = "recon", **kwargs):
    from osprey.services.agent_runner import run_scoped_agent

    _FakeRunner.instances.clear()
    events: list[tuple[str, dict]] = []

    async def on_event(event: str, data: dict) -> None:
        events.append((event, data))

    with patch("osprey.services.agent_runner.get_settings") as mock_settings, \
         patch("cli.agent.loop.Runner", _FakeRunner), \
         patch("cli.agent.tools.EmbeddedToolGateway") as mock_gateway_cls, \
         patch("cli.agent.context.build_system_prompt", return_value="SYSTEM"):
        mock_settings.return_value.llm = _CONFIGURED
        gateway = mock_gateway_cls.return_value

        async def _fake_call(name, args=None):
            return ""

        gateway.call = _fake_call
        result = asyncio.run(
            run_scoped_agent(engagement_id=_eid(), role=role, task="enumerate", on_event=on_event, **kwargs)
        )
    return result, events


def test_scoped_agent_builds_runner_with_role_framing_and_max_turns():
    result, _events = _run(role="exploit", max_turns=5)
    assert len(_FakeRunner.instances) == 1
    runner = _FakeRunner.instances[0]
    assert runner.kwargs["max_turns"] == 5
    assert "exploit" in runner.kwargs["agent_prompt"].lower()
    # allow_spawn isn't passed explicitly for the top-level agent — Runner's
    # own default (True) applies, same as the interactive CLI's top-level loop.
    assert "allow_spawn" not in runner.kwargs
    assert result.error is None
    assert result.success is True


def test_scoped_agent_translates_events_to_job_store_vocabulary():
    result, events = _run(role="recon")
    event_types = [e for e, _ in events]
    # job_store._agent_progress only special-cases these — every one must
    # still arrive, or a real background job silently stops narrating.
    assert "phase_start" in event_types
    assert "tool_start" in event_types
    assert "tool_end" in event_types
    assert "assistant" in event_types
    assert "phase_done" in event_types
    assert "done" in event_types

    tool_end = next(d for e, d in events if e == "tool_end")
    assert tool_end["tool_name"] == "subfinder_scan"
    assert tool_end["success"] is True

    assert result.total_tool_calls == 1
    assert result.total_llm_calls == 1
    assert result.final_message == "Found 3 subdomains, probing them now."
    assert result.phase == "recon"


def test_scoped_agent_worker_factory_caps_spawn_depth_at_one():
    _run(role="recon")
    parent = _FakeRunner.instances[0]
    worker_factory = parent.kwargs["worker_factory"]
    worker = worker_factory(config=None, engagement_id="e1", target="t", tool_filter=None, agent_prompt="")
    assert worker.kwargs["allow_spawn"] is False
