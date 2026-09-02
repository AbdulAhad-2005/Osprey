from __future__ import annotations

import logging
import threading
from collections import deque

from osprey.schemas.audit import AuditAction, AuditLogEntry

logger = logging.getLogger(__name__)


class AuditLog:
    """In-memory append-only audit log.

    Every tool execution is recorded with full context. This is the
    single source of truth for reconstructing what happened during
    an engagement.

    Thread-safe via a lock. The deque is bounded to prevent unbounded
    memory growth; in production this should persist to Postgres.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: deque[AuditLogEntry] = deque(maxlen=max_entries)
        self._lock = threading.Lock()

    def record(self, action: AuditAction) -> AuditLogEntry:
        """Record an audit event and return the entry."""
        entry = AuditLogEntry(action=action)
        with self._lock:
            self._entries.append(entry)
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
        """Query audit log entries with optional filters."""
        with self._lock:
            entries = list(self._entries)

        if engagement_id:
            entries = [e for e in entries if e.action.engagement_id == engagement_id]
        if tool_name:
            entries = [e for e in entries if e.action.tool_name == tool_name]

        return entries[-limit:]

    def count(self, engagement_id: str | None = None) -> int:
        with self._lock:
            if engagement_id is None:
                return len(self._entries)
            return sum(1 for e in self._entries if e.action.engagement_id == engagement_id)

    def recent(self, n: int = 20) -> list[AuditLogEntry]:
        with self._lock:
            return list(self._entries)[-n:]


# Module-level singleton
_audit_log: AuditLog | None = None


def get_audit_log() -> AuditLog:
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog()
    return _audit_log
