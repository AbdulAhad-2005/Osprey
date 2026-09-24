"""Shared runtime scheduler behavior."""

from __future__ import annotations

import asyncio

from osprey.services.engagement_scheduler import EngagementExecutionScheduler


def test_scheduler_caps_combined_callers_per_engagement() -> None:
    async def scenario() -> None:
        scheduler = EngagementExecutionScheduler(lambda: 2)
        active = 0
        peak = 0

        async def worker() -> None:
            nonlocal active, peak
            async with scheduler.tool_slot("eng-1"):
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.01)
                active -= 1

        await asyncio.gather(*(worker() for _ in range(8)))

        assert peak == 2
        assert scheduler.snapshot("eng-1") == {
            "capacity": 2,
            "active": 0,
            "waiting": 0,
        }

    asyncio.run(scenario())


def test_scheduler_keeps_engagement_lanes_independent() -> None:
    async def scenario() -> None:
        scheduler = EngagementExecutionScheduler(lambda: 1)
        both_active = asyncio.Event()
        active: set[str] = set()

        async def worker(engagement_id: str) -> None:
            async with scheduler.tool_slot(engagement_id):
                active.add(engagement_id)
                if len(active) == 2:
                    both_active.set()
                await asyncio.wait_for(both_active.wait(), timeout=0.2)
                active.remove(engagement_id)

        await asyncio.gather(worker("eng-a"), worker("eng-b"))

    asyncio.run(scenario())
