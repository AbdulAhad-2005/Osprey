from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
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
    orchestration: str = "phase_supervisor (deterministic) + phase-agents"


@router.get("/conversation/{engagement_id}", summary="Get the Commander thread for an engagement")
def get_conversation(engagement_id: str, limit: int = 100) -> dict[str, Any]:
    """Server-side conversation so CLI + dashboard share one thread."""
    from osprey.services.conversation_store import get_history

    return {"engagement_id": engagement_id, "messages": get_history(engagement_id, limit=limit)}


@router.delete("/conversation/{engagement_id}", summary="Clear the Commander thread")
def clear_conversation(engagement_id: str) -> dict[str, Any]:
    from osprey.services.conversation_store import clear_history

    return {"engagement_id": engagement_id, "deleted": clear_history(engagement_id)}


@router.get("/events/{engagement_id}", summary="Persistent live activity stream for an engagement")
async def agent_events_stream(engagement_id: str) -> EventSourceResponse:
    """The one live stream for everything happening on this engagement — the
    Commander's own foreground turns AND every background pipeline / spawned
    phase agent's tool calls, correctly attributed via `source`. A client
    opens this ONCE per engagement (not per message) and keeps it open for
    the whole session: "background" work becomes visible here the instant it
    happens, never only on request. Replays recent history first so a client
    that connects (or reconnects) mid-run isn't dropped in with no context.
    """
    from osprey.services import event_bus

    async def event_generator() -> Any:
        async for record in event_bus.subscribe(engagement_id, replay=30):
            yield {
                "event": record["event"],
                "data": json.dumps({**record["data"], "source": record["source"], "ts": record["ts"]}),
            }

    return EventSourceResponse(event_generator())


@router.get("/pipeline-activity/{engagement_id}", summary="Phase readiness + active agent jobs")
def pipeline_activity(engagement_id: str) -> dict[str, Any]:
    """Snapshot for a page load / non-streaming check: conductor phase-readiness
    signals plus any currently active `spawn_agent`-style jobs. A full pentest
    now runs synchronously inside the turn that requested it (visible on that
    turn's own stream) — there is no separate "background pipeline" to report
    on here. This endpoint covers the genuinely-background case (spawn_agent)
    and a live status snapshot without opening a stream.
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
