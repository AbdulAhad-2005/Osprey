"""The Runner's interactive `ask_operator` tool.

Additive capability: only advertised when a caller injects an ``ask_handler``
(the GUI/CLI foreground loop), so the default CLI and headless sub-agents never
see it. Here we drive the loop with a scripted fake model that calls the tool,
and assert the question surfaces as an event and the operator's answer flows
back into the loop so it continues to a final answer.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import cli.agent.loop as loop_mod
from cli.agent.llm import CLIModelConfig
from cli.agent.loop import Runner


class _FakeGateway:
    engagement_id = "eng1"

    def bind(self, **_kwargs) -> None:
        pass

    def schemas(self, budget_tokens: int = 0):
        return []

    async def call(self, name, args):
        return "ok"


def _fake_budget(*_args, **_kwargs):
    # High thresholds → the loop never tries to compact (no litellm needed).
    return SimpleNamespace(compact_at=10**9, context_limit=10**9)


def _run(gen):
    events = []

    async def drain():
        async for ev in gen:
            events.append(ev)

    asyncio.run(drain())
    return events


def test_ask_operator_surfaces_question_and_feeds_answer_back(monkeypatch):
    calls = {"n": 0}
    seen_tools: list[list[str]] = []

    async def fake_complete(*, config, messages, tools, max_tokens):
        calls["n"] += 1
        seen_tools.append([t["function"]["name"] for t in (tools or [])])
        if calls["n"] == 1:
            return {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "function": {
                                        "name": "ask_operator",
                                        "arguments": json.dumps(
                                            {
                                                "question": "Proceed to exploitation?",
                                                "options": [
                                                    {"value": "proceed", "label": "Go", "intent": "danger"},
                                                    {"value": "stop", "label": "Stop"},
                                                ],
                                                "kind": "gate",
                                            }
                                        ),
                                    },
                                }
                            ],
                        }
                    }
                ]
            }
        # Second turn: the tool result (operator's answer) is now in history.
        assert any("operator answered" in (m.get("content") or "").lower() for m in messages)
        return {"choices": [{"message": {"content": "Understood — proceeding.", "tool_calls": []}}]}

    monkeypatch.setattr(loop_mod, "complete", fake_complete)
    monkeypatch.setattr(loop_mod, "build_budget", _fake_budget)

    answered = {"record": None}

    async def ask_handler(record):
        answered["record"] = record
        return "proceed"

    runner = Runner(
        config=CLIModelConfig(model="fake/model", api_key="k"),
        api_base_url="http://localhost:9000",
        engagement_id="eng1",
        allow_spawn=False,
        tool_gateway=_FakeGateway(),
        ask_handler=ask_handler,
    )

    events = _run(runner.run("map and decide"))
    types = [e.type for e in events]

    # The ask tool is advertised to the model.
    assert "ask_operator" in seen_tools[0]
    # A question event surfaced, carrying the options.
    q = [e for e in events if e.type == "question"]
    assert q, f"expected a question event, got {types}"
    assert q[0].data["text"] == "Proceed to exploitation?"
    assert [o["value"] for o in q[0].data["options"]] == ["proceed", "stop"]
    # The handler was invoked, and the loop reached a final answer.
    assert answered["record"] is not None
    done = [e for e in events if e.type == "done"]
    assert done and done[-1].data["content"] == "Understood — proceeding."


def test_ask_operator_not_advertised_without_handler(monkeypatch):
    async def fake_complete(*, config, messages, tools, max_tokens):
        names = [t["function"]["name"] for t in (tools or [])]
        assert "ask_operator" not in names
        return {"choices": [{"message": {"content": "done", "tool_calls": []}}]}

    monkeypatch.setattr(loop_mod, "complete", fake_complete)
    monkeypatch.setattr(loop_mod, "build_budget", _fake_budget)

    runner = Runner(
        config=CLIModelConfig(model="fake/model", api_key="k"),
        api_base_url="http://localhost:9000",
        engagement_id="eng1",
        allow_spawn=False,
        tool_gateway=_FakeGateway(),
    )
    _run(runner.run("hello"))
