"""Commander-owned pipeline run: the ONE standardized way a full engagement runs.

Runs the deterministic conductor (``phase_supervisor.run_pipeline``) IN THE
CALLER'S OWN TURN — synchronously, foreground, fully visible — the same shape
an external harness gets when it spawns its own subagent and watches it work.

This deliberately replaces an earlier design where this call detached into a
background ``asyncio.Task`` and had to be observed through separate
"check status" / "stop" tools. That shape hid a real, standardized, already-
well-briefed pipeline behind a background job, forcing the Commander to poll
for visibility it should have had by default — and left room for the
Commander to keep calling other tools "while it worked", silently duplicating
what the pipeline was already doing. Running it synchronously removes both
problems structurally: every event streams live through the same channel the
caller's turn already uses, and the caller's turn is blocked on this call, so
there is no window for it to freelance in parallel. "Stop" is simply
interrupting the turn (e.g. Ctrl+C in the CLI) — cancellation below cleans up
any phase-agent jobs the conductor had already spawned.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from osprey.services import event_bus

logger = logging.getLogger(__name__)

EventHandler = Callable[[str, dict[str, Any]], Awaitable[None]]


async def run_pipeline_foreground(
    engagement_id: str, run_id: str, emit: EventHandler
) -> dict[str, Any]:
    """Run the conductor to fixpoint, blocking, streaming every event through
    ``emit`` (the caller's own turn) and onto the shared `event_bus` (so a
    second viewer — a future GUI tab on the same engagement — sees it too).
    """
    from osprey.services.phase_supervisor import run_pipeline
    from osprey.services.phase_supervisor import stop_pipeline as _cancel_agent_jobs

    eid = (engagement_id or "").strip()
    if not eid:
        return {"status": "error", "error": "engagement_id required"}
    rid = run_id or uuid.uuid4().hex[:12]

    async def _on_event(event: str, data: dict[str, Any]) -> None:
        event_bus.publish(eid, event, data, source="pipeline")
        await emit(event, data)

    try:
        summary = await run_pipeline(engagement_id=eid, run_id=rid, on_event=_on_event)
        return {"status": "complete", "engagement_id": eid, "run_id": rid, "summary": summary}
    except asyncio.CancelledError:
        logger.info("pipeline run interrupted for engagement %s — cleaning up active agents", eid)
        _cancel_agent_jobs(eid)
        raise
