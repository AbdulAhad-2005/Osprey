"""Durable persistence for engine scan runs.

The in-memory JobStore owns live execution (an asyncio task that cannot survive
a restart anyway); this store persists the *history* — status, results log, and
final report of each engine run — so scan history is queryable across restarts
(dashboard / audit) instead of being lost when the job store prunes or the
backend restarts. Persistence is best-effort: a DB failure here never breaks the
scan itself.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

import orjson
from sqlalchemy import select

from osprey.db.session import SessionLocal
from osprey.models.scan_run import ScanRunRow

logger = logging.getLogger(__name__)


def _dumps(value: Any) -> str:
    try:
        return orjson.dumps(value).decode()
    except Exception:  # noqa: BLE001
        return ""


def _loads(text: str, default: Any) -> Any:
    if not text:
        return default
    try:
        return orjson.loads(text)
    except Exception:  # noqa: BLE001
        return default


class ScanRunStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def upsert(
        self,
        *,
        job_id: str,
        engagement_id: str,
        run_id: str = "",
        kind: str = "expansion",
        label: str = "",
        target: str = "",
        status: str,
        max_passes: int = 0,
        include_low_confidence: bool = False,
        progress: str = "",
        results_log: list[str] | None = None,
        result: dict | None = None,
        error: str = "",
        started_at: float | None = None,
        finished_at: float | None = None,
    ) -> None:
        """Create or update the row for a scan run. Best-effort: never raises."""

        def _ts(v: float | None) -> datetime | None:
            return datetime.fromtimestamp(v, tz=timezone.utc) if v else None

        try:
            with self._lock:
                db = SessionLocal()
                try:
                    row = db.get(ScanRunRow, job_id)
                    if row is None:
                        row = ScanRunRow(id=job_id, engagement_id=engagement_id)
                        db.add(row)
                    row.engagement_id = engagement_id or row.engagement_id
                    row.run_id = run_id or row.run_id
                    row.kind = kind or row.kind
                    row.label = label or row.label
                    row.target = target or row.target
                    row.status = status
                    row.max_passes = max_passes or row.max_passes
                    row.include_low_confidence = 1 if include_low_confidence else row.include_low_confidence
                    if progress:
                        row.progress = progress[:2000]
                    if results_log is not None:
                        row.results_log_json = _dumps(results_log[-500:])
                    if result is not None:
                        row.result_json = _dumps(result)
                    if error:
                        row.error = error[:2000]
                    if started_at is not None and row.started_at is None:
                        row.started_at = _ts(started_at)
                    if finished_at is not None:
                        row.finished_at = _ts(finished_at)
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                finally:
                    db.close()
        except Exception:  # noqa: BLE001
            logger.debug("scan_run persist failed for %s (non-fatal)", job_id, exc_info=True)

    def list_for_engagement(self, engagement_id: str, *, limit: int = 50) -> list[dict]:
        with self._lock:
            db = SessionLocal()
            try:
                rows = db.scalars(
                    select(ScanRunRow)
                    .where(ScanRunRow.engagement_id == engagement_id)
                    .order_by(ScanRunRow.created_at.desc())
                    .limit(max(1, min(limit, 200)))
                ).all()
            finally:
                db.close()
        return [self._to_dict(r) for r in rows]

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            db = SessionLocal()
            try:
                row = db.get(ScanRunRow, job_id)
            finally:
                db.close()
        return self._to_dict(row) if row else None

    def reconcile_orphaned_runs(self) -> int:
        """On startup, mark any run still 'queued'/'running' as failed.

        A job's live execution is an asyncio task that cannot survive a restart,
        so a durable row left in an active state is orphaned — nothing will ever
        move it to a terminal state. This flips those to a clear terminal status
        so poll/list never report a phantom forever-running job. Returns the count
        reconciled. Best-effort: never raises.
        """
        from osprey.schemas.jobs import JobStatus

        now = datetime.now(timezone.utc)
        count = 0
        try:
            with self._lock:
                db = SessionLocal()
                try:
                    rows = db.scalars(
                        select(ScanRunRow).where(
                            ScanRunRow.status.in_(("queued", "running"))
                        )
                    ).all()
                    for row in rows:
                        row.status = JobStatus.FAILED.value
                        if not row.error:
                            row.error = (
                                "Interrupted: the backend restarted while this job was "
                                "still active; the live task did not survive. Re-spawn if "
                                "the phase is still worth running."
                            )
                        if row.finished_at is None:
                            row.finished_at = now
                        count += 1
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                finally:
                    db.close()
        except Exception:  # noqa: BLE001
            logger.debug("reconcile_orphaned_runs failed (non-fatal)", exc_info=True)
        if count:
            logger.info("Reconciled %d orphaned scan run(s) on startup", count)
        return count

    @staticmethod
    def _to_dict(row: ScanRunRow) -> dict:
        return {
            "job_id": row.id,
            "engagement_id": row.engagement_id,
            "run_id": row.run_id,
            "kind": row.kind,
            "label": row.label,
            "target": row.target,
            "status": row.status,
            "max_passes": row.max_passes,
            "include_low_confidence": bool(row.include_low_confidence),
            "progress": row.progress,
            "results_log": _loads(row.results_log_json, []),
            "result": _loads(row.result_json, None),
            "error": row.error,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        }


_store: ScanRunStore | None = None


def get_scan_run_store() -> ScanRunStore:
    global _store
    if _store is None:
        _store = ScanRunStore()
    return _store
