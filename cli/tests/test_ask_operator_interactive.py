"""The interactive terminal CLI's own ask_operator handler.

Before this, only the GUI dashboard chat (foreground_chat.py) wired an
ask_handler into its Runner — the interactive CLI's LLMDriver built its Runner
with none, so ask_operator (the model's exploitation-gate / scope-decision
tool) was never even advertised there. This locks in both halves: the handler
itself answers correctly from terminal input, and LLMDriver._runner() actually
wires it in.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from cli.harness.drivers import LLMDriver, _ask_operator_interactively


def _record(**kw):
    base = {
        "id": "q1",
        "text": "Pull in the newly-found sister domain as in scope?",
        "options": [
            {"value": "new_engagement", "label": "Start a new engagement for it"},
            {"value": "same_engagement", "label": "Keep working the current one"},
            {"value": "skip", "label": "Leave it out, report only"},
        ],
        "kind": "choice",
        "allow_freeform": False,
    }
    base.update(kw)
    return base


def test_answers_by_option_number():
    with patch("builtins.input", return_value="2"):
        answer = asyncio.run(_ask_operator_interactively(_record()))
    assert answer == "same_engagement"


def test_answers_by_option_value_case_insensitive():
    with patch("builtins.input", return_value="SKIP"):
        answer = asyncio.run(_ask_operator_interactively(_record()))
    assert answer == "skip"


def test_freeform_text_passes_through_verbatim():
    with patch("builtins.input", return_value="just the two live ones"):
        answer = asyncio.run(_ask_operator_interactively(_record(allow_freeform=True)))
    assert answer == "just the two live ones"


def test_eof_returns_a_non_answer_not_a_guessed_option():
    """On an unreachable operator, this must NOT silently pick any option —
    including a nominally safe-looking one — since the model treats whatever
    comes back as the operator's real decision."""
    with patch("builtins.input", side_effect=EOFError):
        answer = asyncio.run(_ask_operator_interactively(_record()))
    assert "no answer" in answer.lower()
    assert answer not in {"new_engagement", "same_engagement", "skip"}


def test_keyboard_interrupt_returns_a_non_answer():
    with patch("builtins.input", side_effect=KeyboardInterrupt):
        answer = asyncio.run(_ask_operator_interactively(_record()))
    assert "no answer" in answer.lower()


def test_empty_input_returns_a_non_answer():
    with patch("builtins.input", return_value=""):
        answer = asyncio.run(_ask_operator_interactively(_record()))
    assert "no answer" in answer.lower()


class _FakeWorkers:
    def create(self, **_kw):  # pragma: no cover - not exercised here
        raise AssertionError("workers.create should build sub-agent Runners, not the main one")


class _FakeGateway:
    def bind(self, **_kw):
        pass

    def schemas(self, budget_tokens: int = 0):
        return []


class _FakeRuntime:
    """Just enough of HarnessRuntime for LLMDriver._runner() to build a Runner."""

    def __init__(self):
        self.base_url = "http://localhost:9000"
        self.tool_gateway = _FakeGateway()
        self.workers = _FakeWorkers()
        self.session = SimpleNamespace(active_agent=None)

    @property
    def active_engagement_id(self):
        return "eng1"

    @property
    def active_target(self):
        return "example.test"


def test_llm_driver_wires_ask_handler_into_its_own_runner():
    """The exact gap: LLMDriver's main Runner must offer ask_operator — a
    spawned sub-agent (via runtime.workers.create, not this path) still must
    not, so a headless worker never blocks on a human who isn't there."""
    from agent_core.llm import CLIModelConfig

    with patch.object(CLIModelConfig, "from_env", return_value=CLIModelConfig(model="fake/model", api_key="k")):
        driver = LLMDriver(_FakeRuntime())
        runner = driver._runner()
    assert runner._ask_handler is _ask_operator_interactively
