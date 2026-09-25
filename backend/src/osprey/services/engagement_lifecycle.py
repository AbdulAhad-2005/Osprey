"""Lifecycle operations that span durable and process-local engagement state."""

from __future__ import annotations

from typing import Any

from osprey.services import event_bus
from osprey.services.audit_log import get_audit_log
from osprey.services.commander_context import invalidate_commander_context
from osprey.services.context_delta import clear_context_snapshot_cache
from osprey.services.engagement_scheduler import get_engagement_execution_scheduler
from osprey.services.engagement_store import get_engagement_store
from osprey.services.exec_cache import get_exec_cache
from osprey.services.job_store import get_job_store
from osprey.services.rate_governor import clear_engagement_state
from osprey.services.stdout_index import clear_stdout_index


async def _quiesce(engagement_ids: list[str]) -> int:
    """Cancel and await live work before any durable row is removed."""
    jobs = get_job_store()
    cancelled = 0
    for engagement_id in engagement_ids:
        event_bus.publish(
            engagement_id,
            "engagement_deleting",
            {"engagement_id": engagement_id},
            source="lifecycle",
        )
        cancelled += await jobs.cancel_for_engagement(engagement_id)
    return cancelled


def _clear_process_state(engagement_ids: list[str]) -> int:
    jobs = get_job_store()
    forgotten_jobs = 0
    for engagement_id in engagement_ids:
        forgotten_jobs += jobs.forget_engagement(engagement_id)
        clear_stdout_index(engagement_id)
        clear_context_snapshot_cache(engagement_id)
        invalidate_commander_context(engagement_id)
        clear_engagement_state(engagement_id)
        get_engagement_execution_scheduler().clear_engagement(engagement_id)
        get_audit_log().clear_engagement(engagement_id)
        event_bus.clear_history(engagement_id)

    # Execution-cache keys are intentionally opaque hashes, so there is no safe
    # targeted eviction.  A deletion is rare; clearing the small bounded cache
    # prevents deleted engagement output from remaining reachable in memory.
    if engagement_ids:
        get_exec_cache().clear()
    return forgotten_jobs


async def delete_engagement_safely(engagement_id: str) -> dict[str, Any]:
    """Quiesce work, delete all durable rows, then clear process-local state."""
    eid = (engagement_id or "").strip()
    store = get_engagement_store()
    if not eid or store.get(eid) is None:
        return {"deleted": False, "engagement_id": eid, "reason": "not found"}

    cancelled = await _quiesce([eid])
    result = store.delete(eid)
    if result.get("deleted"):
        result["cancelled_jobs"] = cancelled
        result["cleared_job_records"] = _clear_process_state([eid])
    return result


async def delete_target_engagements_safely(target: str) -> dict[str, Any]:
    """Delete every engagement for a target without racing their live jobs."""
    store = get_engagement_store()
    engagement_ids = store.ids_by_target(target)
    if not engagement_ids:
        return {
            "deleted": False,
            "target": (target or "").strip().lower().rstrip("."),
            "engagements_deleted": 0,
            "reason": f"No engagements found for target '{target}'",
        }

    cancelled = await _quiesce(engagement_ids)
    result = store.delete_by_target(target)
    if result.get("deleted"):
        result["cancelled_jobs"] = cancelled
        result["cleared_job_records"] = _clear_process_state(engagement_ids)
    return result
