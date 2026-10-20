"""Foreground operator chat — the GUI's live conversation loop.

This is the one piece the dashboard needs that no other driver already is: a
*foreground* instance of Osprey's single ReAct loop (``agent_core.loop.Runner``)
whose events stream straight to the browser as they happen, with the operator
able to answer mid-run questions. It is the same loop ``agent_runner`` runs
headlessly for sub-agent jobs — only here the events go to an SSE response
instead of an on_event callback, and the ``ask_operator`` tool is enabled so the
agent can put an exploitation gate / scope decision to the human.

One ``Runner`` is kept per engagement (like the interactive CLI keeps one per
session) so follow-up prompts retain full context; a per-engagement lock
serialises runs. Tool execution still auto-ingests into the shared engagement
stores and still publishes tool_start/tool_end onto ``event_bus`` (so the
legacy live-activity dashboard keeps working) — this service adds nothing to
that path, it only renders the conversation.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from osprey.services import operator_prompts
from osprey.services.agent_common import api_base_url, resolve_model_config
from osprey.services.conversation_store import append_message, get_history

if TYPE_CHECKING:
    from agent_core.loop import Runner
    from agent_core.tools import EmbeddedToolGateway

logger = logging.getLogger(__name__)


@dataclass
class ChatSession:
    """One engagement's live chat state: its Runner (holds the conversation in
    memory across turns) plus the gateway we build system prompts through, so
    callers never reach into Runner internals for the tool caller. Guarded by a
    lock so one engagement runs one turn at a time."""

    runner: "Runner"
    gateway: "EmbeddedToolGateway"
    lock: asyncio.Lock


# One session per engagement, bounded so a long-lived backend doesn't accumulate
# sessions without end. Single-process by design (see event_bus).
_sessions: dict[str, ChatSession] = {}
_SESSION_CAP = 16


def _gate_grant(record: dict[str, Any]) -> tuple[str, list[str]]:
    """Map a 'gate' question to the RoE flag its 'proceed' option should flip."""
    if record.get("kind") != "gate":
        return "", []
    options = record.get("options") or []
    proceed = [
        str(o.get("value"))
        for o in options
        if o.get("intent") in ("danger", "primary")
        or str(o.get("value", "")).lower() in {"proceed", "exploit", "yes", "go", "continue"}
    ]
    # Default to the exploitation flag; a destructive gate can be signalled by a
    # 'destructive' value but exploitation is the common case.
    field = "allow_exploitation"
    if any("destruct" in str(o.get("value", "")).lower() for o in options):
        field = "destructive_actions_allowed"
    return field, proceed


def _get_session(engagement_id: str, config, api_base: str) -> ChatSession:
    from agent_core.loop import Runner
    from agent_core.tools import EmbeddedToolGateway
    from osprey.services.engagement_store import get_engagement_store

    session = _sessions.get(engagement_id)
    if session is not None:
        return session

    engagement = get_engagement_store().get(engagement_id) if engagement_id else None
    target = engagement.target if engagement else ""
    gateway = EmbeddedToolGateway(api_base)
    if engagement_id:
        gateway.bind(engagement_id=engagement_id, target=target)

    def worker_factory(*, config, engagement_id, target, tool_filter, agent_prompt):
        return Runner(
            config=config,
            api_base_url=api_base,
            engagement_id=engagement_id,
            target=target,
            allow_spawn=False,
            tool_filter=tool_filter,
            agent_prompt=agent_prompt,
            tool_gateway=gateway,
            worker_factory=worker_factory,
        )

    async def ask_handler(record: dict[str, Any]) -> str:
        grant_field, grant_true = _gate_grant(record)
        pq = operator_prompts.open_question(
            engagement_id,
            question_id=record["id"],
            text=record["text"],
            options=record["options"],
            kind=record.get("kind", "choice"),
            allow_freeform=bool(record.get("allow_freeform", False)),
            grant_field=grant_field,
            grant_true_values=grant_true,
        )
        return await pq.future

    runner = Runner(
        config=config,
        api_base_url=api_base,
        engagement_id=engagement_id,
        target=target,
        tool_gateway=gateway,
        worker_factory=worker_factory,
        ask_handler=ask_handler,
    )
    # Seed textual history so a backend restart still continues the thread
    # (tool-call detail isn't persisted; findings are, and remain queryable).
    history = get_history(engagement_id)
    if history:
        runner.messages = [{"role": m["role"], "content": m["content"]} for m in history]

    if len(_sessions) >= _SESSION_CAP:
        _sessions.pop(next(iter(_sessions)), None)  # evicts the session + its lock together
    session = ChatSession(runner=runner, gateway=gateway, lock=asyncio.Lock())
    _sessions[engagement_id] = session
    return session


async def stream_chat(engagement_id: str, prompt: str) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Yield (event_name, data) pairs for the SSE endpoint. Never raises into the
    response — a failure becomes an ``error`` + ``done`` so the UI always closes
    the turn cleanly."""
    eid = (engagement_id or "").strip()
    prompt = (prompt or "").strip()
    if not eid or not prompt:
        yield ("error", {"message": "engagement_id and prompt are required."})
        yield ("done", {"content": ""})
        return

    config = resolve_model_config()
    if config is None:
        msg = (
            "No model configured. Set LLM_MODEL and LLM_API_KEY in the project .env "
            "(any LiteLLM provider), then try again. You can also use Demo mode to "
            "preview the interface without a key."
        )
        yield ("error", {"message": msg})
        yield ("done", {"content": ""})
        return

    from agent_core.context import build_system_prompt

    session = _get_session(eid, config, api_base_url())
    await session.lock.acquire()
    try:
        runner = session.runner
        append_message(eid, "user", prompt)
        system_prompt = await build_system_prompt(eid, tool_caller=session.gateway.call)

        final_text = ""
        async for ev in runner.run(prompt, system_prompt=system_prompt):
            name, data = _translate(ev)
            if name is None:
                continue
            if ev.type == "assistant_text":
                final_text = data.get("content", "") or final_text
            elif ev.type == "done":
                final_text = data.get("content", "") or final_text
            yield (name, data)
        if final_text and not final_text.startswith("(stopped:"):
            append_message(eid, "assistant", final_text)
    except Exception as exc:  # noqa: BLE001 — never crash the response
        logger.exception("foreground chat error engagement=%s", eid)
        yield ("error", {"message": f"Chat loop error: {exc}"})
        yield ("done", {"content": ""})
    finally:
        operator_prompts.cancel_for_engagement(eid, reason="(run ended)")
        session.lock.release()


def _translate(ev) -> tuple[str | None, dict[str, Any]]:
    t = ev.type
    d = ev.data or {}
    if t == "llm_call_start":
        return ("llm_call_start", {})
    if t == "llm_still_waiting":
        return ("llm_still_waiting", {"elapsed_seconds": d.get("elapsed_seconds", 0)})
    if t == "thinking":
        return ("thinking", {"content": d.get("content", "")})
    if t == "assistant_text":
        return ("assistant", {"content": d.get("content", "")})
    if t == "tool_start":
        return (
            "tool_start",
            {
                "tool_name": d.get("tool_name", ""),
                "arguments": _arg_str(d.get("arguments")),
                "tool_call_id": d.get("tool_call_id", ""),
                "source": "commander",
            },
        )
    if t == "tool_end":
        return (
            "tool_end",
            {
                "tool_name": d.get("tool_name", ""),
                "result": d.get("result", ""),
                "success": bool(d.get("success", True)),
                "duration_seconds": d.get("duration_seconds", 0),
                "tool_call_id": d.get("tool_call_id", ""),
            },
        )
    if t == "question":
        return ("question", d)
    if t == "compaction":
        return ("compaction", {"messages_after": d.get("messages_after")})
    if t == "error":
        return ("error", {"message": d.get("message", "")})
    if t == "done":
        return ("done", {"content": d.get("content", "")})
    if t == "cancelled":
        return ("cancelled", {})
    return (None, {})


def _arg_str(arguments: Any) -> str:
    if arguments is None:
        return "{}"
    if isinstance(arguments, str):
        return arguments
    try:
        return json.dumps(arguments)
    except (TypeError, ValueError):
        return str(arguments)
