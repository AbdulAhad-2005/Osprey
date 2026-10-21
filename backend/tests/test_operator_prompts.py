"""Interactive operator-prompt registry: the backend side of the GUI/CLI
'agent pauses mid-run to ask the operator' feature."""

from __future__ import annotations

import asyncio

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.services import operator_prompts
from osprey.services.engagement_store import get_engagement_store


def test_open_question_then_answer_resolves_future_and_clears():
    async def scenario() -> str:
        pq = operator_prompts.open_question(
            "eng-op",
            text="Proceed?",
            options=[{"value": "go", "label": "Go"}, {"value": "stop", "label": "Stop"}],
            kind="gate",
        )
        payload = pq.event_payload()
        assert payload["id"] == pq.id
        assert payload["kind"] == "gate"
        assert operator_prompts.list_open("eng-op"), "question should be listed while open"

        result = operator_prompts.answer(pq.id, "go")
        assert result is not None and result["answer"] == "go"
        return await asyncio.wait_for(pq.future, timeout=2)

    assert asyncio.run(scenario()) == "go"
    # Once answered it is removed from the open set.
    assert operator_prompts.list_open("eng-op") == []


def test_answer_unknown_question_returns_none():
    assert operator_prompts.answer("does-not-exist", "x") is None


def test_double_answer_is_ignored():
    async def scenario() -> None:
        pq = operator_prompts.open_question(
            "eng-dbl", text="q?", options=[{"value": "a", "label": "A"}]
        )
        assert operator_prompts.answer(pq.id, "a") is not None
        # Already answered / removed → second answer is a no-op.
        assert operator_prompts.answer(pq.id, "a") is None
        await asyncio.wait_for(pq.future, timeout=2)

    asyncio.run(scenario())


def test_cancel_for_engagement_resolves_pending():
    async def scenario() -> str:
        pq = operator_prompts.open_question(
            "eng-cancel", text="q?", options=[{"value": "a", "label": "A"}, {"value": "b", "label": "B"}]
        )
        operator_prompts.cancel_for_engagement("eng-cancel", reason="stopped")
        return await asyncio.wait_for(pq.future, timeout=2)

    assert asyncio.run(scenario()) == "stopped"
    assert operator_prompts.list_open("eng-cancel") == []


def test_gate_grant_sets_roe_flag():
    store = get_engagement_store()
    eng = store.create(EngagementCreateRequest(target="grant.test"))

    async def scenario() -> None:
        pq = operator_prompts.open_question(
            eng.id,
            text="Cross into exploitation?",
            options=[
                {"value": "stop", "label": "Stop at findings"},
                {"value": "go", "label": "Proceed", "intent": "danger"},
            ],
            kind="gate",
            grant_field="allow_exploitation",
            grant_true_values=["go"],
        )
        # Operator declines → the flag is driven to False, regardless of default.
        operator_prompts.answer(pq.id, "stop")
        await asyncio.wait_for(pq.future, timeout=2)

    asyncio.run(scenario())
    refreshed = store.get(eng.id)
    assert refreshed is not None
    assert refreshed.rules_of_engagement.allow_exploitation is False
