from __future__ import annotations

import json
import logging
import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from osprey.services.llm_service import get_llm_service, llm_configured
from osprey.services.tool_discovery import get_tools_for_llm_phase

logger = logging.getLogger(__name__)
router = APIRouter()


class AgentStatusResponse(BaseModel):
    model: str
    model_active: bool
    tools_available: int
    recon_tools: int = 0
    network_tools: int = 0
    engine: str = "litellm"
    pipeline: str = "conductor"
    orchestration: str = "CLI driver + explicit scoped phase-agents"


@router.get("/conversation/{engagement_id}", summary="Get the saved conversation for an engagement")
def get_conversation(engagement_id: str, limit: int = 100) -> dict[str, Any]:
    """Server-side conversation so CLI + dashboard share one thread."""
    from osprey.services.conversation_store import get_history

    return {"engagement_id": engagement_id, "messages": get_history(engagement_id, limit=limit)}


@router.get("/chat-events/{engagement_id}", summary="Resume the durable operator transcript")
async def chat_events(
    engagement_id: str,
    after: int = Query(default=0, ge=0),
    wait_seconds: float = Query(default=0, ge=0, le=25),
    include_legacy: bool = True,
) -> dict[str, Any]:
    from osprey.services.chat_transcript import page_events
    from osprey.services.foreground_chat import run_active, run_state

    deadline = asyncio.get_running_loop().time() + wait_seconds
    while True:
        events = await asyncio.to_thread(page_events, engagement_id, after)
        active = run_active(engagement_id)
        if events or not active or asyncio.get_running_loop().time() >= deadline:
            from osprey.services.conversation_store import get_history

            return {
                "events": events, "active": active,
                "cursor": events[-1]["id"] if events else after,
                "has_more": len(events) == 500,
                "run": run_state(engagement_id),
                "legacy_messages": (
                    get_history(engagement_id, limit=100, before_id=events[0]["data"].get("message_id") if events else None)
                    if include_legacy and after == 0 and (not events or events[0]["data"].get("message_id")) else []
                ),
            }
        await asyncio.sleep(0.5)


@router.delete("/conversation/{engagement_id}", summary="Clear the saved conversation")
async def clear_conversation(engagement_id: str) -> dict[str, Any]:
    from osprey.services.conversation_store import clear_history
    from osprey.services.foreground_chat import settle_session

    await settle_session(engagement_id, forget=True)

    return {"engagement_id": engagement_id, "deleted": clear_history(engagement_id)}


@router.get("/events/{engagement_id}", summary="Persistent live activity stream for an engagement")
async def agent_events_stream(engagement_id: str, replay: int = 30) -> EventSourceResponse:
    """The one live stream for everything happening on this engagement — the
    foreground driver activity and every spawned phase agent's tool calls,
    correctly attributed via `source`. A client
    opens this ONCE per engagement (not per message) and keeps it open for
    the whole session: "background" work becomes visible here the instant it
    happens, never only on request. Replays recent history first so a client
    that connects (or reconnects) mid-run isn't dropped in with no context.
    """
    from osprey.services import event_bus

    async def event_generator() -> Any:
        async for record in event_bus.subscribe(engagement_id, replay=max(0, replay)):
            yield {
                "event": record["event"],
                "data": json.dumps({**record["data"], "source": record["source"], "ts": record["ts"]}),
            }

    return EventSourceResponse(event_generator())


@router.get("/pipeline-activity/{engagement_id}", summary="Phase readiness + active agent jobs")
def pipeline_activity(engagement_id: str) -> dict[str, Any]:
    """Snapshot for a page load / non-streaming check: phase-readiness signals
    plus any currently active explicit scoped-agent jobs. The CLI or external
    harness owns the root execution loop; this endpoint only reports backend
    state without opening a stream.
    """
    from osprey.services.job_store import get_job_store
    from osprey.services.phase_supervisor import (
        phase_readiness_snapshot,
        phase_readiness_text,
        pipeline_status_line,
    )

    eid = (engagement_id or "").strip()
    snapshot = phase_readiness_snapshot(eid) if eid else {}
    active = [a.model_dump() for a in get_job_store().list_active_agents(eid)] if eid else []
    return {
        "engagement_id": eid,
        "active_agents": active,
        "agents_line": pipeline_status_line(eid) if eid else "",
        "phase_readiness": snapshot,
        "phase_readiness_text": phase_readiness_text(snapshot) if snapshot else "",
    }


class ChatRequest(BaseModel):
    engagement_id: str
    prompt: str
    interrupt: bool = False
    request_id: str = Field(default="", max_length=128)


@router.post("/chat/start", status_code=202, summary="Accept a message and continue this engagement")
async def start_chat(req: ChatRequest) -> dict[str, Any]:
    from osprey.services.engagement_store import get_engagement_store
    from osprey.services.foreground_chat import start_chat as admit

    if get_engagement_store().get(req.engagement_id) is None:
        raise HTTPException(404, "Engagement not found")
    return await admit(req.engagement_id, req.prompt, interrupt=req.interrupt, request_id=req.request_id)


@router.post("/chat", summary="Foreground operator chat — live SSE event stream")
async def agent_chat(req: ChatRequest) -> EventSourceResponse:
    """Run the one ReAct loop in the foreground for a GUI/CLI operator and stream
    its events (assistant text, reasoning, tool_start/tool_end with full output,
    interactive questions, done) as Server-Sent Events. The agent may pause with
    an `ask_operator` question; answer it via POST /agent/question/{id}/answer to
    resume the same open stream. Needs LLM_MODEL/LLM_API_KEY configured."""
    from osprey.services.foreground_chat import stream_chat
    from osprey.services.foreground_chat import run_active
    from osprey.services.engagement_store import get_engagement_store

    if req.engagement_id and get_engagement_store().get(req.engagement_id) is None:
        raise HTTPException(404, "Engagement not found")
    if run_active(req.engagement_id):
        raise HTTPException(409, "A run is already in progress. Wait for it to finish or Stop it before sending another message.")

    async def event_generator() -> Any:
        async for name, data in stream_chat(req.engagement_id, req.prompt):
            yield {"event": name, "data": json.dumps(data)}

    # ping keeps the stream alive through the long human-wait on a question.
    return EventSourceResponse(event_generator(), ping=15)


class AnswerRequest(BaseModel):
    engagement_id: str = ""
    answer: str


@router.get("/run-status/{engagement_id}", summary="Whether a background chat run is in flight")
def run_status(engagement_id: str) -> dict[str, Any]:
    """Lets a (re)connecting client know a run is still going for this engagement
    so it can re-attach to the live stream instead of showing a dead chat."""
    from osprey.services.foreground_chat import run_active, run_state

    return {"engagement_id": engagement_id, "active": run_active(engagement_id), **run_state(engagement_id)}


@router.post("/stop/{engagement_id}", summary="Stop the in-flight chat run")
async def stop_run(engagement_id: str) -> dict[str, Any]:
    """Cancel the background run for this engagement (the Stop button). The run's
    cleanup publishes a terminal ``cancelled``/``done`` onto the event bus."""
    from osprey.services.foreground_chat import run_active, settle_session

    was_active = run_active(engagement_id)
    await settle_session(engagement_id)
    return {"engagement_id": engagement_id, "stopped": was_active}


@router.post("/question/{question_id}/answer", summary="Answer an interactive operator question")
async def answer_question(question_id: str, req: AnswerRequest) -> dict[str, Any]:
    from osprey.services import operator_prompts
    from osprey.services.chat_transcript import record_answer

    if req.engagement_id and not any(q["id"] == question_id for q in operator_prompts.list_open(req.engagement_id)):
        return {"ok": False, "reason": "Question is not open in this engagement"}

    result = operator_prompts.answer(question_id, req.answer)
    if result is None:
        return {"ok": False, "reason": "unknown or already-answered question"}
    record_answer(result["engagement_id"], question_id, req.answer)
    return {"ok": True, **result}


@router.get("/questions/{engagement_id}", summary="List open interactive questions")
def open_questions(engagement_id: str) -> dict[str, Any]:
    from osprey.services import operator_prompts

    return {
        "engagement_id": engagement_id,
        "questions": operator_prompts.list_open(engagement_id),
    }


@router.get("/status", summary="Get agent status")
async def agent_status() -> AgentStatusResponse:
    llm_service = get_llm_service()
    tools = get_tools_for_llm_phase("auto")

    return AgentStatusResponse(
        model=llm_service.model,
        model_active=llm_configured(),
        tools_available=len(tools),
        recon_tools=len(tools),
        network_tools=len(tools),
    )
