"""Server-side Commander conversation, one thread per engagement.

CLI and dashboard both read/append here, so they share a single thread instead
of each carrying its own request-local history. This is the persistence the GUI
needs to render and resume a conversation.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select

from osprey.db.session import SessionLocal
from osprey.models.conversation import ConversationMessageRow

_MAX_TURNS_DEFAULT = 40


def append_message(engagement_id: str, role: str, content: str) -> None:
    eid = (engagement_id or "").strip()
    if not eid or role not in ("user", "assistant") or not (content or "").strip():
        return
    db = SessionLocal()
    try:
        db.add(ConversationMessageRow(engagement_id=eid, role=role, content=content))
        db.commit()
    finally:
        db.close()


def get_history(engagement_id: str, *, limit: int = _MAX_TURNS_DEFAULT) -> list[dict[str, Any]]:
    """Return the most recent messages as OpenAI-style {role, content} dicts."""
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    db = SessionLocal()
    try:
        rows = list(
            db.scalars(
                select(ConversationMessageRow)
                .where(ConversationMessageRow.engagement_id == eid)
                .order_by(ConversationMessageRow.id.desc())
                .limit(max(1, limit))
            )
        )
    finally:
        db.close()
    rows.reverse()
    return [{"role": r.role, "content": r.content} for r in rows]


def clear_history(engagement_id: str) -> int:
    eid = (engagement_id or "").strip()
    if not eid:
        return 0
    db = SessionLocal()
    try:
        result = db.execute(
            delete(ConversationMessageRow).where(ConversationMessageRow.engagement_id == eid)
        )
        db.commit()
        return int(result.rowcount or 0)
    finally:
        db.close()
