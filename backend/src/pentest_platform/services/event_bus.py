"""The one engagement-scoped live event bus.

Every tool-executing loop for an engagement — the Commander's own turn, a
`launch_pipeline`-spawned phase agent, a one-off `spawn_agent` job — publishes
into this single place. Any listener (the CLI's persistent stream, a future
GUI tab) subscribes once per engagement and sees *everything* happening for
it, correctly attributed, instead of reconciling three separate silos.

This is the fix for the "background pipeline is invisible" defect: a harness
has exactly one locus of visible activity. "Background" means the caller
doesn't block waiting for it — it never means the work is hidden from the
user. A bounded per-engagement history lets a subscriber that connects (or
reconnects) mid-run catch up instead of missing everything that already ran.

Single-process, in-memory by design — this platform is local-first (see the
GUI-ready guardrail); there is exactly one backend process per deployment, so
an `asyncio.Queue`-based fan-out needs no external broker.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator
from typing import Any

_HISTORY_CAP = 300
_QUEUE_CAP = 500

_history: dict[str, deque[dict[str, Any]]] = {}
_subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}


def publish(engagement_id: str, event: str, data: dict[str, Any], *, source: str = "") -> None:
    """Record + fan out one event. Never blocks: a full/slow subscriber queue
    drops its own oldest entry rather than stalling the publisher — losing
    backlog for one slow viewer must never slow down the pentest itself."""
    eid = (engagement_id or "").strip()
    if not eid:
        return
    record = {"ts": time.time(), "event": event, "source": source, "data": data}
    _history.setdefault(eid, deque(maxlen=_HISTORY_CAP)).append(record)
    for queue in list(_subscribers.get(eid, ())):
        try:
            queue.put_nowait(record)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
                queue.put_nowait(record)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass


def history(engagement_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Bounded recent history — used both for a subscriber's catch-up replay
    and for a plain pull-style snapshot (e.g. a REST status call)."""
    eid = (engagement_id or "").strip()
    buf = _history.get(eid)
    if not buf:
        return []
    return list(buf)[-limit:]


def is_active(engagement_id: str) -> bool:
    return bool(_subscribers.get((engagement_id or "").strip()))


async def subscribe(engagement_id: str, *, replay: int = 20) -> AsyncIterator[dict[str, Any]]:
    """Async-iterate every event for an engagement: recent history first (so a
    late/reconnecting subscriber isn't dropped into the middle of a run with
    no context), then live events until the caller stops iterating."""
    eid = (engagement_id or "").strip()
    if not eid:
        return
    for record in history(eid, limit=replay):
        yield record
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_QUEUE_CAP)
    _subscribers.setdefault(eid, set()).add(queue)
    try:
        while True:
            yield await queue.get()
    finally:
        _subscribers.get(eid, set()).discard(queue)
