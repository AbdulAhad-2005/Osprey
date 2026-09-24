"""Shared per-engagement runtime capacity for external tool executions.

Callers used to create independent semaphores in the expansion engine, bulk
fan-out, and agent loop while direct API calls and background jobs bypassed
them.  Each individual path looked bounded, but their combined subprocess
count was not.  The kernel now owns one queue per engagement; callers retain
full capability and simply wait for a configured slot instead of oversubscribing
the Kali execution backend.
"""

from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Callable


@dataclass
class _Lane:
    semaphore: asyncio.Semaphore
    capacity: int
    active: int = 0
    waiting: int = 0


class EngagementExecutionScheduler:
    """Loop-safe collection of per-engagement execution lanes."""

    def __init__(self, capacity_provider: Callable[[], int]) -> None:
        self._capacity_provider = capacity_provider
        self._lanes: dict[tuple[int, str], _Lane] = {}
        self._guard = threading.RLock()

    def _lane(self, engagement_id: str) -> _Lane:
        loop_id = id(asyncio.get_running_loop())
        eid = (engagement_id or "").strip().lower()
        capacity = max(1, int(self._capacity_provider()))
        key = (loop_id, eid)
        with self._guard:
            lane = self._lanes.get(key)
            # Honor a reloaded capacity as soon as the lane is idle.  Replacing
            # a live semaphore would strand its waiters, so an active lane keeps
            # its current capacity until naturally drained.
            if lane is None or (
                lane.capacity != capacity and lane.active == 0 and lane.waiting == 0
            ):
                lane = _Lane(asyncio.Semaphore(capacity), capacity)
                self._lanes[key] = lane
            return lane

    @asynccontextmanager
    async def tool_slot(self, engagement_id: str) -> AsyncIterator[None]:
        lane = self._lane(engagement_id)
        with self._guard:
            lane.waiting += 1
        try:
            await lane.semaphore.acquire()
        finally:
            with self._guard:
                lane.waiting = max(0, lane.waiting - 1)
        with self._guard:
            lane.active += 1
        try:
            yield
        finally:
            with self._guard:
                lane.active = max(0, lane.active - 1)
            lane.semaphore.release()

    def snapshot(self, engagement_id: str) -> dict[str, int]:
        """Return aggregate active/waiting counts across live event loops."""
        eid = (engagement_id or "").strip().lower()
        with self._guard:
            lanes = [lane for (_, key), lane in self._lanes.items() if key == eid]
            return {
                "capacity": max((lane.capacity for lane in lanes), default=max(1, int(self._capacity_provider()))),
                "active": sum(lane.active for lane in lanes),
                "waiting": sum(lane.waiting for lane in lanes),
            }

    def clear_engagement(self, engagement_id: str) -> None:
        """Drop idle lanes for a deleted engagement; live leases drain safely."""
        eid = (engagement_id or "").strip().lower()
        with self._guard:
            for key, lane in list(self._lanes.items()):
                if key[1] == eid and lane.active == 0 and lane.waiting == 0:
                    self._lanes.pop(key, None)


def _configured_capacity() -> int:
    from osprey.services.parallelism_config import max_running_jobs

    return max_running_jobs()


_SCHEDULER = EngagementExecutionScheduler(_configured_capacity)


def get_engagement_execution_scheduler() -> EngagementExecutionScheduler:
    return _SCHEDULER
