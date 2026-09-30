"""No LLM configured used to be a hard error with no way forward short of
editing .env and restarting. It now offers the one thing that still works
without a model: the deterministic opportunity engine, with an explicit
fresh-vs-reuse choice — never a silent default either way.
"""

from __future__ import annotations

from unittest.mock import patch

from cli.agent.llm import LLMNotConfiguredError
from cli.commands.prompt import handle_prompt


class _FakeRuntime:
    def __init__(self) -> None:
        self.drive_prompt_calls: list[str] = []

    def drive_prompt(self, prompt: str, sink) -> bool:
        self.drive_prompt_calls.append(prompt)
        raise LLMNotConfiguredError("No driving model configured for this CLI.")


class _FakeClient:
    def __init__(self) -> None:
        self.compile_calls: list[tuple[str, bool]] = []
        self.bound: dict | None = None

    def compile_engagement_for_target(self, target: str, force_new: bool = False):
        self.compile_calls.append((target, force_new))
        return {"id": "eng-1", "target": target, "reused": not force_new}

    def execution_status(self):
        return {"ready": True}


def _patched(monkeypatch, runtime: _FakeRuntime):
    monkeypatch.setattr("cli.commands.prompt.get_runtime", lambda client: runtime)


def test_decline_leaves_only_the_original_error(monkeypatch, capsys):
    runtime = _FakeRuntime()
    _patched(monkeypatch, runtime)
    client = _FakeClient()

    with patch("builtins.input", return_value="n"):
        result = handle_prompt("samaa.tv", client)

    assert result is False
    assert client.compile_calls == []


def test_accept_with_default_continue_reuses_existing_engagement(monkeypatch):
    runtime = _FakeRuntime()
    _patched(monkeypatch, runtime)
    client = _FakeClient()
    engine_calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        "cli.commands.prompt._run_engine_scan",
        lambda client, target, **kw: engine_calls.append((target, kw.get("supervised", False))) or True,
    )
    monkeypatch.setattr("cli.commands.prompt._bind_engagement", lambda client, data: None)

    with patch("builtins.input", side_effect=["y", ""]):
        result = handle_prompt("samaa.tv", client)

    assert result is True
    assert client.compile_calls == [("samaa.tv", False)]  # "continue" (default) -> not force_new
    assert engine_calls == [("samaa.tv", False)]


def test_accept_with_fresh_forces_a_new_engagement(monkeypatch):
    runtime = _FakeRuntime()
    _patched(monkeypatch, runtime)
    client = _FakeClient()
    monkeypatch.setattr("cli.commands.prompt._run_engine_scan", lambda client, target, **kw: True)
    monkeypatch.setattr("cli.commands.prompt._bind_engagement", lambda client, data: None)

    with patch("builtins.input", side_effect=["y", "fresh"]):
        result = handle_prompt("samaa.tv", client)

    assert result is True
    assert client.compile_calls == [("samaa.tv", True)]


def test_ctrl_c_during_the_offer_declines_cleanly(monkeypatch):
    runtime = _FakeRuntime()
    _patched(monkeypatch, runtime)
    client = _FakeClient()

    with patch("builtins.input", side_effect=KeyboardInterrupt):
        result = handle_prompt("samaa.tv", client)

    assert result is False
    assert client.compile_calls == []


def test_invalid_target_after_accepting_reports_the_backend_error(monkeypatch):
    runtime = _FakeRuntime()
    _patched(monkeypatch, runtime)

    class _RejectingClient(_FakeClient):
        def compile_engagement_for_target(self, target: str, force_new: bool = False):
            raise ValueError("not a valid target")

    client = _RejectingClient()

    with patch("builtins.input", side_effect=["y", ""]):
        result = handle_prompt("what should I do next", client)

    assert result is False
