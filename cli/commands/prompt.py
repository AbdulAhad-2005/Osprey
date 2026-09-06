from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cli.api.client import APIClient

from rich.markdown import Markdown
from rich.markup import escape

from cli.agent.context import build_system_prompt
from cli.agent.llm import CLIModelConfig, LLMNotConfiguredError
from cli.agent.loop import Runner
from cli.ui.display import console, print_error, print_info


def _get_runner(client: "APIClient") -> Runner | None:
    """One Runner per CLI session, lazily created and cached on the client —
    so a follow-up prompt keeps full conversation context, same as any real
    agent CLI, instead of starting fresh every message."""
    existing: Runner | None = getattr(client, "agent_runner", None)
    if existing is not None:
        return existing
    try:
        config = CLIModelConfig.from_env()
    except LLMNotConfiguredError as exc:
        print_error(str(exc))
        return None
    runner = Runner(config=config, api_base_url=client.base_url)
    client.agent_runner = runner
    return runner


def _get_loop(client: "APIClient") -> asyncio.AbstractEventLoop:
    """One event loop for the whole CLI session, not a fresh one per prompt.

    litellm keeps process-wide async singletons (its LoggingWorker spawns a
    background task bound to whichever loop is running when it's first
    touched). A new loop per prompt orphans that task on the previous,
    now-closed loop the moment a second prompt runs — surfacing as "Task was
    destroyed but it is pending!" and, worse, a real asyncio.CancelledError
    raised somewhere inside that broken state and mistaken for a genuine
    Ctrl+C by this loop's own cancellation handling. One loop for the session
    (closed only when the CLI itself exits) is the correct lifecycle for a
    long-running interactive process — not a special case for litellm.
    """
    loop: asyncio.AbstractEventLoop | None = getattr(client, "agent_loop", None)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        client.agent_loop = loop
    return loop


def handle_prompt(prompt: str, client: "APIClient") -> None:
    """Drive the CLI's own local agent loop and render its output live.

    The `Runner` and its conversation history, and the event loop itself,
    persist on `client` across prompts. Ctrl+C cancels the in-flight task
    cleanly via a real `asyncio.CancelledError` — not by abandoning an HTTP
    stream and hoping something notices.
    """
    if not prompt.strip():
        return

    runner = _get_runner(client)
    if runner is None:
        return

    loop = _get_loop(client)
    asyncio.set_event_loop(loop)
    task = loop.create_task(_drive(prompt, client, runner))
    try:
        loop.run_until_complete(task)
    except KeyboardInterrupt:
        task.cancel()
        try:
            loop.run_until_complete(task)
        except asyncio.CancelledError:
            pass
    except Exception as exc:  # noqa: BLE001 — final safety net: nothing that
        # can go wrong mid-turn (a bug in tool dispatch, an event-rendering
        # error, an LLM exception type friendly_llm_error doesn't recognize)
        # should ever take down the whole interactive session.
        print_error(f"Turn failed: {exc}")


async def _drive(prompt: str, client: "APIClient", runner: Runner) -> None:
    system_prompt = ""
    if not runner.messages:
        system_prompt = await build_system_prompt(client.active_engagement_id or "")

    try:
        async for event in runner.run(prompt, system_prompt=system_prompt):
            _render(event)
    except asyncio.CancelledError:
        raise


_BOILERPLATE_LINE_RE = re.compile(r"^(#{1,6}\s|target:|engagement_id:|run_id:)", re.I)
_SUCCESS_RE = re.compile(r"(?im)^success:\s*(true|false)\b")
# Priority order for what's actually worth showing, checked in this order —
# not "first N lines," which mechanically hit only structural fields (the
# status line, **COMMAND:**, **TOOL:**) and never reached **ERROR:**, the one
# line that explains *why* a call failed, several lines further down.
_PRIORITY_PREFIXES = ("**ERROR:**", "**PARSED SUMMARY:**", "**Note:**")


def _tool_failed(result: str) -> bool:
    """The platform's own `success: True/False` field is the real signal —
    my own dispatch-level `ERROR executing ...` string (a Python exception,
    never reaching the platform at all) is a second, separate failure case
    that field can't cover. Checking only one of the two meant a
    platform-reported failure (success: False) still rendered a green ✓."""
    if result.startswith("ERROR"):
        return True
    match = _SUCCESS_RE.search(result)
    return bool(match) and match.group(1).lower() == "false"


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


def _render(event) -> None:  # noqa: ANN001 — cli.agent.loop.Event, avoid import cycle noise
    if event.type == "thinking":
        content = (event.data.get("content") or "").strip()
        if content:
            console.print(f"[dim italic]{escape(content)}[/]")
    elif event.type == "tool_start":
        name = event.data.get("tool_name", "?")
        try:
            args = json.loads(event.data.get("arguments") or "{}")
        except (json.JSONDecodeError, ValueError):
            args = {}
        preview = ", ".join(f"{k}={v}" for k, v in args.items() if v not in (None, "", [], {}))
        console.print(f"  [bold cyan]▶[/] [bold]{escape(name)}[/][dim]({escape(preview[:100])})[/]")
    elif event.type == "tool_end":
        name = event.data.get("tool_name", "?")
        elapsed = event.data.get("duration_seconds", 0.0)
        result = event.data.get("result", "") or ""
        failed = _tool_failed(result)
        icon, style = ("✗", "red") if failed else ("✓", "green")
        console.print(f"  [{style}]{icon}[/] [{style}]{escape(name)}[/] [dim]({elapsed:.1f}s)[/]")
        for line in _preview_lines(result, limit=3):
            console.print(f"      [dim]{escape(line[:220])}[/]")
    elif event.type == "assistant_text":
        pass  # rendered once via "done" below to avoid double-printing
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
