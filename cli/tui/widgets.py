"""Shell widgets: the sidebar and the input() modal."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Input, Label, Static


class Sidebar(VerticalScroll):
    """Live engagement context: binding, model, context-token HUD, phase
    readiness. Update methods take already-formatted renderables so the app
    owns formatting and this stays a dumb view."""

    def compose(self) -> ComposeResult:
        yield Label("Engagement", classes="s-title first")
        yield Static("not bound", id="s_eng")
        yield Label("Phases", classes="s-title")
        yield Static("—", id="s_phases")
        yield Label("Findings", classes="s-title")
        yield Static("[dim]none yet[/]", id="s_findings")
        yield Label("Session", classes="s-title")
        yield Static("[dim]0 tool calls[/]", id="s_session")
        yield Label("Context", classes="s-title")
        yield Static("[dim]no LLM turn yet[/]", id="s_tokens")
        yield Label("Model", classes="s-title")
        yield Static("…", id="s_model")

    def set_engagement(self, value) -> None:
        self.query_one("#s_eng", Static).update(value)

    def set_model(self, value) -> None:
        self.query_one("#s_model", Static).update(value)

    def set_tokens(self, value) -> None:
        self.query_one("#s_tokens", Static).update(value)

    def set_phases(self, value) -> None:
        self.query_one("#s_phases", Static).update(value)

    def set_findings(self, value) -> None:
        self.query_one("#s_findings", Static).update(value)

    def set_session(self, value) -> None:
        self.query_one("#s_session", Static).update(value)


class PromptModal(ModalScreen[str]):
    """A one-line modal so a handler's ``input()`` (engagement name, an
    ask_operator gate) works inside the TUI instead of deadlocking on the
    stdin the app owns."""

    def __init__(self, question: str) -> None:
        super().__init__()
        self._question = question

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label(self._question or "Input:", id="q")
            yield Input(id="answer")

    def on_mount(self) -> None:
        self.query_one("#answer", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)
