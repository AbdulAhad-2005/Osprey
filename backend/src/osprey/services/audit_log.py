"""Durable append-only execution audit log with an in-memory failure buffer."""

from __future__ import annotations

import logging
import threading
from collections import deque

import orjson
from sqlalchemy import func, select

from osprey.db.session import SessionLocal
from osprey.models.audit_entry import AuditEntryRow
from osprey.schemas.audit import AuditAction, AuditLogEntry

logger = logging.getLogger(__name__)


def _encode(value: dict) -> str:
    return orjson.dumps(value).decode()


def _decode(value: str) -> dict:
    try:
        decoded = orjson.loads(value or "{}")
        return decoded if isinstance(decoded, dict) else {}
    except orjson.JSONDecodeError:
        return {}


def _row_to_entry(row: AuditEntryRow) -> AuditLogEntry:
    return AuditLogEntry(
        id=row.id,
        timestamp=row.created_at,
        action=AuditAction(
            tool_name=row.tool_name,
            target=row.target,
            engagement_id=row.engagement_id or None,
            run_id=row.run_id,
            command=row.command,
            success=bool(row.success),
            returncode=row.returncode,
            duration_seconds=row.duration_seconds,
            error=row.error or None,
            recovery_action=row.recovery_action or None,
            alternative_tool=row.alternative_tool or None,
            metadata=_decode(row.metadata_json),
        ),
    )


class AuditLog:
    """Persist every execution; buffer only writes that temporarily fail."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: deque[AuditLogEntry] = deque(maxlen=max_entries)
        self._unpersisted: set[str] = set()
        self._lock = threading.RLock()

    def record(self, action: AuditAction) -> AuditLogEntry:
        entry = AuditLogEntry(action=action)
        with self._lock:
            self._entries.append(entry)
            try:
                db = SessionLocal()
                try:
                    db.add(
                        AuditEntryRow(
                            id=entry.id,
                            engagement_id=action.engagement_id or "",
                            run_id=action.run_id or "",
                            tool_name=action.tool_name,
                            target=action.target,
                            command=action.command,
                            success=1 if action.success else 0,
                            returncode=action.returncode,
                            duration_seconds=action.duration_seconds,
                            error=action.error or "",
                            recovery_action=action.recovery_action or "",
                            alternative_tool=action.alternative_tool or "",
                            metadata_json=_encode(action.metadata),
                            created_at=entry.timestamp,
                        )
                    )
                    db.commit()
                    self._unpersisted.discard(entry.id)
                except Exception:
                    db.rollback()
                    self._unpersisted.add(entry.id)
                    logger.warning(
                        "Audit persistence failed; buffered entry %s in memory",
                        entry.id,
                        exc_info=True,
                    )
                finally:
                    db.close()
            except Exception:
                self._unpersisted.add(entry.id)
                logger.warning(
                    "Audit database unavailable; buffered entry %s in memory",
                    entry.id,
                    exc_info=True,
                )
        logger.info(
            "AUDIT: tool=%s target=%s success=%s",
            action.tool_name,
            action.target,
            action.success,
        )
        return entry

    def query(
        self,
        engagement_id: str | None = None,
        tool_name: str | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        limit = max(1, min(int(limit), 10_000))
        with self._lock:
            persisted: list[AuditLogEntry] = []
            try:
                db = SessionLocal()
                try:
                    stmt = select(AuditEntryRow)
                    if engagement_id:
                        stmt = stmt.where(AuditEntryRow.engagement_id == engagement_id)
                    if tool_name:
                        stmt = stmt.where(AuditEntryRow.tool_name == tool_name)
                    rows = db.scalars(
                        stmt.order_by(AuditEntryRow.created_at.desc()).limit(limit)
                    ).all()
                    persisted = [_row_to_entry(row) for row in reversed(rows)]
                finally:
                    db.close()
            except Exception:
                logger.debug("Durable audit query failed; using memory", exc_info=True)

            buffered = [
                entry
                for entry in self._entries
                if entry.id in self._unpersisted
                and (not engagement_id or entry.action.engagement_id == engagement_id)
                and (not tool_name or entry.action.tool_name == tool_name)
            ]
            merged = {entry.id: entry for entry in (*persisted, *buffered)}
            return sorted(
                merged.values(), key=lambda entry: entry.timestamp.timestamp()
            )[-limit:]

    def count(self, engagement_id: str | None = None) -> int:
        with self._lock:
            durable_count = 0
            try:
                db = SessionLocal()
                try:
                    stmt = select(func.count()).select_from(AuditEntryRow)
                    if engagement_id:
                        stmt = stmt.where(AuditEntryRow.engagement_id == engagement_id)
                    durable_count = int(db.scalar(stmt) or 0)
                finally:
                    db.close()
            except Exception:
                logger.debug("Durable audit count failed; using memory", exc_info=True)
            buffered_count = sum(
                1
                for entry in self._entries
                if entry.id in self._unpersisted
                and (not engagement_id or entry.action.engagement_id == engagement_id)
            )
            return durable_count + buffered_count

    def recent(self, n: int = 20) -> list[AuditLogEntry]:
        return self.query(limit=n)

    def clear_engagement(self, engagement_id: str) -> None:
        """Remove fallback-buffer entries after durable engagement deletion."""
        eid = (engagement_id or "").strip()
        with self._lock:
            self._entries = deque(
                (entry for entry in self._entries if entry.action.engagement_id != eid),
                maxlen=self._entries.maxlen,
            )
            retained_ids = {entry.id for entry in self._entries}
            self._unpersisted.intersection_update(retained_ids)


_audit_log: AuditLog | None = None


def get_audit_log() -> AuditLog:
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog()
    return _audit_log
