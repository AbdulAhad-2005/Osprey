from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cli.api.client import APIClient

from rich.markdown import Markdown
from rich.markup import escape

from cli.agent.llm import LLMNotConfiguredError
from cli.agent.loop import tool_result_failed
from cli.commands.scan_shared import _api_error_text, _bind_engagement, _run_engine_scan
from cli.harness import get_runtime
from cli.ui.display import (
    console,
    print_error,
    print_info,
    print_tool_end_live,
    print_tool_start_live,
)


def handle_prompt(prompt: str, client: "APIClient") -> bool:
    """Drive the CLI's own local agent loop and render its output live.

    The `Runner`, its conversation history, and the event loop persist on the
    CLI's `HarnessRuntime` across prompts. Ctrl+C cancels the in-flight task
    cleanly via a real `asyncio.CancelledError` — not by abandoning an HTTP
    stream and hoping something notices.
    """
    if not prompt.strip():
        return True

    runtime = get_runtime(client)
    renderer = _PromptRenderer(runtime)
    try:
        return runtime.drive_prompt(prompt, renderer.render)
    except LLMNotConfiguredError as exc:
        return _offer_no_llm_fallback(str(exc), prompt.strip(), client)
    except Exception as exc:  # noqa: BLE001 — final safety net: nothing that
        # can go wrong mid-turn (a bug in tool dispatch, an event-rendering
        # error, an LLM exception type friendly_llm_error doesn't recognize)
        # should ever take down the whole interactive session.
        print_error(f"Turn failed: {exc}")
        return False
    finally:
        renderer.close()


def _offer_no_llm_fallback(error_text: str, prompt: str, client: "APIClient") -> bool:
    """No LLM configured means the free ReAct loop can't run at all — rather
    than just error out, offer the one thing that still works without a
    model: the deterministic opportunity engine (``/scan --engine``'s driver)
    against ``prompt`` treated as a target. Declining leaves the original
    error as the only output, unchanged from before this existed.
    """
    print_error(error_text)
    try:
        answer = input(
            f'Run the no-LLM deterministic engine against "{prompt}" as a target instead? [y/N]: '
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if answer not in ("y", "yes"):
        return False

    try:
        fresh_answer = input(
            "Start a fresh engagement, or continue an existing one for this target if any? [fresh/continue] (continue): "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    force_new = fresh_answer in ("f", "fresh", "new")

    try:
        data = client.compile_engagement_for_target(prompt, force_new=force_new)
        _bind_engagement(client, data)
    except Exception as exc:  # noqa: BLE001 — this is a fallback path; report and stop, don't chain further errors
        print_error(_api_error_text(exc))
        return False

    return _run_engine_scan(client, prompt)


class _PromptRenderer:
    def __init__(self, runtime) -> None:  # noqa: ANN001
        self.runtime = runtime
        self.thinking = console.status("[dim]Thinking…[/]", spinner="dots")
        self.spinner_on = False

    def render(self, event) -> None:  # noqa: ANN001
        try:
            if event.type == "llm_call_start":
                if not self.spinner_on:
                    self.thinking.start()
                    self.spinner_on = True
                self.thinking.update("[dim]Thinking…[/]")
                return
            if event.type == "llm_still_waiting":
                elapsed = int(event.data.get("elapsed_seconds") or 0)
                if self.spinner_on:
                    self.thinking.update(
                        f"[dim]Still waiting on the LLM provider… ({elapsed}s)[/]"
                    )
                return
            if self.spinner_on:
                self.thinking.stop()
                self.spinner_on = False
            _render(event, self.runtime.transcript)
        finally:
            if event.type in {"done", "error", "cancelled"} and self.spinner_on:
                self.thinking.stop()
                self.spinner_on = False

    def close(self) -> None:
        if self.spinner_on:
            self.thinking.stop()
            self.spinner_on = False


_BOILERPLATE_LINE_RE = re.compile(r"^(#{1,6}\s|target:|engagement_id:|run_id:)", re.I)
# Priority order for what's actually worth showing, checked in this order —
# not "first N lines," which mechanically hit only structural fields (the
# status line, **COMMAND:**, **TOOL:**) and never reached **ERROR:**, the one
# line that explains *why* a call failed, several lines further down.
_PRIORITY_PREFIXES = ("**ERROR:**", "**PARSED SUMMARY:**", "**Note:**")


def _tool_failed(result: str) -> bool:
    """Render a tool line red when it failed OR was blocked by a loop guard.
    Delegates the real failure signal to the canonical detector in the loop
    (single source of truth); adds the guard-block string, which is a
    CLI-loop synthetic result, not a platform failure."""
    return tool_result_failed(result) or result.startswith("BLOCKED (")


def _preview_lines(result: str, *, limit: int) -> list[str]:
    """The lines of a tool result actually worth showing: whichever priority
    field is present (the failure reason first, since that's what you need
    when something's red), else the first `limit` non-boilerplate lines."""
    lines = [ln.strip() for ln in result.strip().splitlines() if ln.strip()]
    picked: list[str] = []
    for prefix in _PRIORITY_PREFIXES:
        picked.extend(ln for ln in lines if ln.startswith(prefix))
    if picked:
        return picked[:limit]
    return [ln for ln in lines if not _BOILERPLATE_LINE_RE.match(ln)][:limit]


def _render(event, transcript) -> None:  # noqa: ANN001 — event/transcript runtime types
    if event.type == "thinking":
        content = (event.data.get("content") or "").strip()
        if content:
            console.print(f"[dim italic]{escape(content)}[/]")
    elif event.type == "tool_start":
        # Delegate to the shared, transcript-backed renderer so a local-loop tool
        # call gets a #id, /tool N detail, /details levels and the tool-history
        # table — exactly like a background phase-agent call. One renderer, not two.
        name = event.data.get("tool_name", "?")
        try:
            args = json.loads(event.data.get("arguments") or "{}")
        except (json.JSONDecodeError, ValueError):
            args = {}
        print_tool_start_live(
            name,
            args,
            {"tool_call_id": event.data.get("tool_call_id", "")},
            transcript=transcript,
        )
    elif event.type == "tool_end":
        name = event.data.get("tool_name", "?")
        result = event.data.get("result", "") or ""
        # The local loop returns a raw result string; adapt it to the transcript's
        # shape (success incl. the loop-guard BLOCKED case, plus the worth-showing
        # preview lines) so rendering matches the background-event path.
        print_tool_end_live(
            name,
            {
                "tool_name": name,
                "success": not _tool_failed(result),
                "duration_seconds": event.data.get("duration_seconds", 0.0),
                "preview": result,
                "display_preview": _preview_lines(result, limit=3),
                "tool_call_id": event.data.get("tool_call_id", ""),
            },
            transcript=transcript,
        )
    elif event.type == "assistant_text":
        pass  # rendered once via "done" below to avoid double-printing
    elif event.type == "compaction":
        # Context management is non-destructive — the full record stays in
        # durable memory; this just shows the working window was compacted.
        limit = event.data.get("context_limit")
        tokens = event.data.get("context_tokens")
        if event.data.get("forced"):
            detail = "context window hit — summarized older turns and retried"
        elif tokens and limit:
            detail = f"~{tokens} tok approaching {limit} limit — summarized older turns"
        else:
            detail = "summarized older turns to free context"
        console.print(f"  [dim]· context compacted ({detail}); full record kept in memory[/]")
    elif event.type == "error":
        print_error(event.data.get("message") or "The model request failed.")
    elif event.type == "done":
        content = (event.data.get("content") or "").strip()
        if content and not content.startswith("(stopped:"):
            console.print()
            console.print(Markdown(content))
    elif event.type == "cancelled":
        print_info("Stopped — here's everything found before you stopped:")
        findings = (event.data.get("findings") or "").strip()
        if findings:
            console.print(Markdown(findings))
