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
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from osprey.services import operator_prompts
from osprey.services.agent_common import api_base_url, resolve_model_config
from osprey.services.conversation_store import append_message
from osprey.services.llm_service import llm_configured, llm_configured_reason

# System-prompt preparation (a context-packet tool call) runs before the ReAct
# loop emits anything; tick progress to the UI this often, and give up after the
# cap so a hung backend surfaces an error instead of an endless spinner.
_PREP_TICK_SECONDS = 3.0
_PREP_MAX_SECONDS = 60.0

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
    config: Any


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


def _get_session(engagement_id: str, config, api_base: str, exclude_run: str = "") -> ChatSession:
    from agent_core.loop import Runner
    from agent_core.tools import EmbeddedToolGateway
    from osprey.services.engagement_store import get_engagement_store

    session = _sessions.get(engagement_id)
    previous_messages = None
    if session is not None:
        # Apply Settings changes on the next turn, retaining conversation state.
        # An in-flight turn keeps its original provider/key consistently.
        if session.config != config and not session.lock.locked():
            previous_messages = session.runner.messages
            _sessions.pop(engagement_id, None)
        else:
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
        max_turns=0,  # Interactive work ends on model completion or operator pause.
    )
    # Restore root tool exchanges and narration from the same durable journal
    # the dashboard reads, including after a process restart or session eviction.
    from osprey.services.chat_transcript import restore_history
    runner.messages = restore_history(engagement_id, exclude_run=exclude_run)
    if previous_messages is not None:
        runner.messages = previous_messages

    if len(_sessions) >= _SESSION_CAP:
        for key, candidate in list(_sessions.items()):
            if not candidate.lock.locked() and not run_active(key):
                _sessions.pop(key, None)
                break
    session = ChatSession(runner=runner, gateway=gateway, lock=asyncio.Lock(), config=config)
    _sessions[engagement_id] = session
    return session


# One background run per engagement. The agent loop runs here as a task that
# publishes every event to the shared event bus — NOT tied to the SSE client's
# connection. So a refresh / navigate-away no longer kills a long assessment, and
# any client (the original, or a reconnecting one) sees the run by subscribing to
# the journal. One run per engagement; redirect admission settles the old turn
# before starting the next one.
_active_runs: dict[str, "asyncio.Task[None]"] = {}
_run_progress: dict[str, dict[str, Any]] = {}
_admission_locks: dict[str, asyncio.Lock] = {}


def run_state(engagement_id: str) -> dict[str, Any]:
    from osprey.services.chat_transcript import latest_event

    if run_active(engagement_id):
        return {"state": "running", "resumable": False, **_run_progress.get(engagement_id, {})}
    last = latest_event(engagement_id)
    if not last:
        return {"state": "idle", "resumable": False}
    data = last["data"]
    reason = data.get("reason", "")
    content = data.get("content", "")
    if last["event"] == "done" and not reason:
        reason = ("turn_limit" if "turn limit" in content else
                  "paused" if content == "(stopped)" else
                  "empty_response" if not content.strip() else "completed")
    state = "completed" if reason == "completed" else "paused" if reason in {"paused", "turn_limit"} else "interrupted"
    from osprey.services.engagement_store import get_engagement_store
    engagement = get_engagement_store().get(engagement_id)
    still_open = engagement is not None and engagement.status not in {"completed", "complete"}
    # Finishing one model response does not establish assessment completion.
    return {"state": state, "reason": reason or "interrupted", "resumable": state != "completed" or still_open, "run_id": last["run_id"]}


async def start_chat(engagement_id: str, prompt: str, *, interrupt: bool = False, request_id: str = "") -> dict[str, Any]:
    """Admit input before returning HTTP success; execution outlives its client."""
    from fastapi import HTTPException
    from osprey.services.chat_transcript import admit_input, accepted_input

    eid, prompt = engagement_id.strip(), prompt.strip()
    if not eid or not prompt:
        raise HTTPException(422, "engagement_id and prompt are required.")
    async with _admission_locks.setdefault(eid, asyncio.Lock()):
        previous = accepted_input(eid, request_id)
        if previous is not None:
            return {"accepted": True, "run_id": previous["run_id"], "event_id": previous["id"]}
        config = resolve_model_config()
        if config is None or not llm_configured():
            raise HTTPException(400, "No usable model is configured. Open Settings and choose a model/provider. " + llm_configured_reason())
        if run_active(eid):
            if not interrupt:
                raise HTTPException(409, "A run is already in progress.")
            await settle_session(eid)
        run_id = uuid.uuid4().hex
        record = admit_input(eid, run_id, prompt, request_id)
        _run_progress[eid] = {"stage": "preparing", "message": "Preparing engagement context…", "run_id": run_id}
        _active_runs[eid] = asyncio.create_task(_drive_run(eid, prompt, config, run_id=run_id))
        return {"accepted": True, "run_id": run_id, "event_id": record["id"]}


def run_active(engagement_id: str) -> bool:
    """True when a background run is in flight for this engagement."""
    task = _active_runs.get((engagement_id or "").strip())
    return bool(task) and not task.done()


def stop_run(engagement_id: str) -> bool:
    """Cancel the in-flight run for this engagement (the Stop button). Returns
    whether a run was actually cancelled."""
    task = _active_runs.get((engagement_id or "").strip())
    if task and not task.done():
        task.cancel()
        return True
    return False


async def settle_session(engagement_id: str, *, forget: bool = False) -> None:
    """Settle execution before pause, redirect, chat clearing or deletion."""
    task = _active_runs.get(engagement_id)
    stop_run(engagement_id)
    if task is not None:
        await asyncio.gather(task, return_exceptions=True)
    if forget:
        _sessions.pop(engagement_id, None)


async def _drive_run(eid: str, prompt: str, config, *, run_id: str = "") -> None:
    """Drive the agent loop for one prompt, publishing every event to the shared
    event bus and persisting the assistant reply. Runs as a background task so it
    survives the originating client's disconnect; clients view it by subscribing
    to the bus (``event_bus.subscribe``). Never raises out (cooperative cancel and
    errors both become terminal bus events) so the task always cleans up."""
    from agent_core.context import build_system_prompt
    from osprey.services import event_bus
    from osprey.services.chat_transcript import TRANSIENT_EVENTS, append_event

    admitted = bool(run_id)
    run_id = run_id or uuid.uuid4().hex

    def emit(name: str, data: dict[str, Any]) -> None:
        data = dict(data)
        data["run_id"] = run_id
        if name in TRANSIENT_EVENTS:
            _run_progress[eid] = {"stage": name, **data}
        elif name == "tool_start":
            _run_progress[eid] = {"stage": "working", "run_id": run_id}
        elif name == "question":
            _run_progress[eid] = {"stage": "question", "message": "Waiting for your answer…", "run_id": run_id}
        if name not in TRANSIENT_EVENTS:
            record = append_event(eid, run_id, name, data)
            data["event_id"] = record["id"]
        event_bus.publish(eid, name, data, source="commander")

    session = None
    final_text = ""
    persisted = False
    prompt_task = None
    runner_started = False
    try:
        session = _get_session(eid, config, api_base_url(), run_id if admitted else "")
        await session.lock.acquire()
        if not admitted:
            message_id = append_message(eid, "user", prompt)
            emit("run_start", {"prompt": prompt, "message_id": message_id})
        emit("status", {"stage": "preparing", "message": "Preparing engagement context…"})
        prompt_task = asyncio.ensure_future(
            build_system_prompt(eid, tool_caller=session.gateway.call)
        )
        waited = 0.0
        while not prompt_task.done():
            await asyncio.wait({prompt_task}, timeout=_PREP_TICK_SECONDS)
            if prompt_task.done():
                break
            waited += _PREP_TICK_SECONDS
            if waited >= _PREP_MAX_SECONDS:
                prompt_task.cancel()
                raise TimeoutError(
                    f"Preparing engagement context timed out after {int(waited)}s "
                    "(the backend context call did not return). Check the backend logs."
                )
            emit("status", {"stage": "preparing", "message": f"Preparing engagement context… ({int(waited)}s)"})
        system_prompt = prompt_task.result()

        runner_started = True
        async for ev in session.runner.run(prompt, system_prompt=system_prompt):
            name, data = _translate(ev)
            if name is None:
                continue
            if ev.type in ("assistant_text", "done"):
                final_text = data.get("content", "") or final_text
            emit(name, data)
        if final_text and not final_text.startswith("(stopped:"):
            append_message(eid, "assistant", final_text)
            persisted = True
    except asyncio.CancelledError:
        # Explicit Stop. Keep any partial reply, then close the turn cleanly.
        if final_text and not persisted and not final_text.startswith("(stopped:"):
            append_message(eid, "assistant", final_text)
            persisted = True
        emit("cancelled", {"findings": ""})
        emit("done", {"content": "", "reason": "paused"})
    except Exception as exc:  # noqa: BLE001 — never let the task crash
        logger.exception("foreground chat error engagement=%s", eid)
        _sessions.pop(eid, None)  # Rebuild any interrupted tool batch from the journal.
        if final_text and not persisted and not final_text.startswith("(stopped:"):
            append_message(eid, "assistant", final_text)
            persisted = True
        try:
            emit("error", {"message": f"Chat loop error: {exc}"})
            emit("done", {"content": "", "reason": "error"})
        except Exception:
            # A journal/database failure must not leave connected clients
            # waiting forever for a terminal event that cannot be persisted.
            logger.exception("Could not persist chat termination engagement=%s", eid)
            event_bus.publish(eid, "error", {"message": "Chat stopped because its transcript could not be saved. Check backend storage before retrying."}, source="commander")
            event_bus.publish(eid, "done", {"content": ""}, source="commander")
    finally:
        if prompt_task is not None and not prompt_task.done():
            prompt_task.cancel()
            await asyncio.gather(prompt_task, return_exceptions=True)
        operator_prompts.cancel_for_engagement(eid, reason="(run ended)")
        if session is not None and session.lock.locked():
            session.lock.release()
        _active_runs.pop(eid, None)
        _run_progress.pop(eid, None)
        if not runner_started:
            # A prompt accepted during preparation still belongs to history.
            # Rebuild from the journal if preparation was interrupted or failed.
            _sessions.pop(eid, None)


async def stream_chat(engagement_id: str, prompt: str) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Compatibility SSE view over the same admitted run and durable journal.

    Disconnecting stops observation only. Concurrent submissions are rejected
    by admission; GUI redirects use the separate JSON admission endpoint.
    """

    eid = (engagement_id or "").strip()
    prompt = (prompt or "").strip()
    if not eid or not prompt:
        yield ("error", {"message": "engagement_id and prompt are required."})
        yield ("done", {"content": ""})
        return

    # Pre-flight the model *before* any slow work so a missing/undialable model
    # fails in under a second with a clear, actionable message (pointing at the
    # Settings surface) instead of a silent multi-minute spinner.
    config = resolve_model_config()
    if config is None or not llm_configured():
        reason = llm_configured_reason() if config is not None else ""
        detail = f" ({reason})" if reason else ""
        msg = (
            f"No usable model is configured{detail}. Open Settings (or set LLM_MODEL and "
            "LLM_API_KEY in the project .env — any LiteLLM provider) and try again. "
            "Demo mode previews the interface without a key."
        )
        yield ("error", {"message": msg})
        yield ("done", {"content": ""})
        return

    from fastapi import HTTPException
    from osprey.services.chat_transcript import page_events

    try:
        accepted = await start_chat(eid, prompt)
    except HTTPException as exc:
        yield ("error", {"message": str(exc.detail)})
        yield ("done", {"content": "", "reason": "error"})
        return
    cursor = accepted["event_id"] - 1
    previous_progress = None
    # Compatibility SSE clients use the same admission and journal as the GUI.
    # Their disconnect cannot cancel execution or lose an accepted input.
    while True:
        records = await asyncio.to_thread(page_events, eid, cursor)
        for record in records:
            cursor = record["id"]
            if record["run_id"] != accepted["run_id"]:
                continue
            yield (record["event"], {**record["data"], "event_id": record["id"]})
            if record["event"] == "done":
                return
        progress = _run_progress.get(eid)
        if progress and progress != previous_progress:
            stage = progress.get("stage", "")
            event = stage if stage in {"llm_call_start", "llm_still_waiting"} else "status"
            yield (event, progress)
            previous_progress = dict(progress)
        if not run_active(eid) and not records:
            return
        await asyncio.sleep(0.25)


def _translate(ev) -> tuple[str | None, dict[str, Any]]:
    t = ev.type
    d = ev.data or {}
    if t == "llm_call_start":
        return ("llm_call_start", {})
    if t == "llm_still_waiting":
        return ("llm_still_waiting", {"elapsed_seconds": d.get("elapsed_seconds", 0)})
    if t == "thinking":
        # This is the model's public message accompanying tool calls, not its
        # private reasoning. Render it as ordinary assistant narration.
        return ("assistant", {"content": d.get("content", ""), "source": d.get("source", "commander")})
    if t == "assistant_text":
        return ("assistant", {"content": d.get("content", "")})
    if t == "tool_start":
        return (
            "tool_start",
            {
                "tool_name": d.get("tool_name", ""),
                "arguments": _arg_str(d.get("arguments")),
                "tool_call_id": d.get("tool_call_id", ""),
                "source": d.get("source", "commander"),
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
        if d.get("source", "").startswith("worker-"):
            return ("assistant", {"content": f"Worker error: {d.get('message', '')}"})
        return ("error", {"message": d.get("message", "")})
    if t == "done":
        return ("done", {"content": d.get("content", ""), "reason": d.get("reason", "completed"), "finish_reason": d.get("finish_reason", "")})
    if t == "status":
        return ("status", d)
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
