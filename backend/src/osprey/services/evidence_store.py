"""Queryable Evidence rows — plans/harness/02-evidence-and-observation-layer.md Step 1.

A promotion of what ``stdout_index``/``artifacts`` already write, not new
storage: callers pass in the ``stdout_path``/``stderr_path`` they already
resolved (see ``services/tool_execution.py``); this store just makes that a
queryable, durable row every ``Observation`` can cite via ``evidence_id``.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from osprey.db.session import SessionLocal
from osprey.models.evidence import EvidenceRow
from osprey.schemas.observation import Evidence


def _row_to_evidence(row: EvidenceRow) -> Evidence:
    return Evidence(
        id=row.id,
        engagement_id=row.engagement_id,
        run_id=row.run_id,
        tool_name=row.tool_name,
        target=row.target,
        command=row.command,
        stdout_path=row.stdout_path,
        stderr_path=row.stderr_path,
        exit_code=row.exit_code,
        duration_ms=row.duration_ms,
        observed=bool(row.observed),
        created_at=row.created_at,
    )


class EvidenceStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def record(
        self,
        *,
        engagement_id: str,
        tool_name: str,
        run_id: str = "",
        target: str = "",
        command: str = "",
        stdout_path: str = "",
        stderr_path: str = "",
        exit_code: int = 0,
        duration_ms: int = 0,
    ) -> Evidence | None:
        eid = (engagement_id or "").strip()
        if not eid:
            return None
        row = EvidenceRow(
            id=uuid.uuid4().hex[:12],
            engagement_id=eid,
            run_id=run_id or "",
            tool_name=(tool_name or "")[:128],
            target=(target or "")[:512],
            command=command or "",
            stdout_path=(stdout_path or "")[:512],
            stderr_path=(stderr_path or "")[:512],
            exit_code=int(exit_code or 0),
            duration_ms=int(duration_ms or 0),
            observed=False,
        )
        with self._lock:
            db = SessionLocal()
            try:
                db.add(row)
                db.commit()
                db.refresh(row)
                return _row_to_evidence(row)
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

    def mark_observed(self, evidence_id: str) -> None:
        eid = (evidence_id or "").strip()
        if not eid:
            return
        with self._lock:
            db = SessionLocal()
            try:
                row = db.get(EvidenceRow, eid)
                if row is not None and not row.observed:
                    row.observed = True
                    db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

    def get(self, evidence_id: str) -> Evidence | None:
        eid = (evidence_id or "").strip()
        if not eid:
            return None
        with self._lock:
            db = SessionLocal()
            try:
                row = db.get(EvidenceRow, eid)
                return _row_to_evidence(row) if row is not None else None
            finally:
                db.close()

    def list_for_engagement(
        self, engagement_id: str, *, unobserved_only: bool = False, limit: int = 200
    ) -> list[Evidence]:
        eid = (engagement_id or "").strip()
        if not eid:
            return []
        with self._lock:
            db = SessionLocal()
            try:
                stmt = select(EvidenceRow).where(EvidenceRow.engagement_id == eid)
                if unobserved_only:
                    stmt = stmt.where(EvidenceRow.observed.is_(False))
                stmt = stmt.order_by(EvidenceRow.created_at.desc()).limit(max(1, min(int(limit), 2000)))
                rows = list(db.scalars(stmt).all())
            finally:
                db.close()
        return [_row_to_evidence(r) for r in rows]


_store: EvidenceStore | None = None
_store_lock = threading.Lock()


def get_evidence_store() -> EvidenceStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = EvidenceStore()
    return _store
