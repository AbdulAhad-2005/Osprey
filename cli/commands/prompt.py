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
from cli.agent.loop import Runner, tool_result_failed
from cli.ui.display import (
    console,
    print_error,
    print_info,
    print_tool_end_live,
    print_tool_start_live,
)


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
    # Apply the active prompt-defined agent/flow, if any: its optional model
    # override and its tool scope. Switching agents resets client.agent_runner
    # (see /agent), so the next call here rebuilds with the new mode.
    agent = getattr(client, "active_agent", None)
    tool_filter = None
    if agent is not None:
        if agent.model:
            from dataclasses import replace
            config = replace(config, model=agent.model)
        tool_filter = agent.tool_allowed
    runner = Runner(
        config=config,
        api_base_url=client.base_url,
        engagement_id=client.active_engagement_id or "",
        target=client.active_target or "",
        tool_filter=tool_filter,
        agent_prompt=(agent.prompt if agent is not None else ""),
    )
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


def handle_prompt(prompt: str, client: "APIClient") -> bool:
    """Drive the CLI's own local agent loop and render its output live.

    The `Runner` and its conversation history, and the event loop itself,
    persist on `client` across prompts. Ctrl+C cancels the in-flight task
    cleanly via a real `asyncio.CancelledError` — not by abandoning an HTTP
    stream and hoping something notices.
    """
    if not prompt.strip():
        return True

    runner = _get_runner(client)
    if runner is None:
        return False

    loop = _get_loop(client)
    asyncio.set_event_loop(loop)
    task = loop.create_task(_drive(prompt, client, runner))
    try:
        return bool(loop.run_until_complete(task))
    except KeyboardInterrupt:
        task.cancel()
        try:
            loop.run_until_complete(task)
        except asyncio.CancelledError:
            pass
        return False
    except Exception as exc:  # noqa: BLE001 — final safety net: nothing that
        # can go wrong mid-turn (a bug in tool dispatch, an event-rendering
        # error, an LLM exception type friendly_llm_error doesn't recognize)
        # should ever take down the whole interactive session.
        print_error(f"Turn failed: {exc}")
        return False


async def _drive(prompt: str, client: "APIClient", runner: Runner) -> bool:
    system_prompt = ""
    if not runner.messages:
        agent = getattr(client, "active_agent", None)
        system_prompt = await build_system_prompt(
            client.active_engagement_id or "",
            tool_budget_active=runner.config.tool_schema_budget_tokens > 0,
            agent_prompt=(agent.prompt if agent is not None else ""),
        )

    # The one genuinely silent gap in a turn — the model call itself (seconds,
    # sometimes 10+ with complete()'s own retry-with-backoff) had zero visible
    # feedback before this: the loop yields "llm_call_start" right before each
    # call and nothing else until it returns, so from here it either looked
    # frozen or, worse, looked like the previous line was the final answer.
    # Owned entirely here (not in cli/agent/loop.py) — that module stays
    # UI-agnostic, this is the one place that already renders everything.
    thinking = console.status("[dim]Thinking…[/]", spinner="dots")
    spinner_on = False
    succeeded = True
    try:
        async for event in runner.run(prompt, system_prompt=system_prompt):
            if event.type == "llm_call_start":
                if not spinner_on:
                    thinking.start()
                    spinner_on = True
                continue
            if event.type == "error":
                succeeded = False
            elif event.type == "done" and str(event.data.get("content") or "").startswith(
                "(stopped:"
            ):
                succeeded = False
            if spinner_on:
                thinking.stop()
                spinner_on = False
            _render(event)
    except asyncio.CancelledError:
        raise
    finally:
        if spinner_on:
            thinking.stop()
    return succeeded


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


def _render(event) -> None:  # noqa: ANN001 — cli.agent.loop.Event, avoid import cycle noise
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
        print_tool_start_live(name, args, {"tool_call_id": event.data.get("tool_call_id", "")})
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
