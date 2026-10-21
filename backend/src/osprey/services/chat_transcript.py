"""Append and page transcript events; IDs are the reconnect cursor.

Only operator-visible events are written, not spinner heartbeats. This leaves
the tool execution hot path and its observation ingestion unchanged.
"""
import json
from typing import Any

from sqlalchemy import select

from osprey.db.session import SessionLocal
from osprey.models.chat_event import ChatEventRow


TRANSIENT_EVENTS = {"status", "llm_call_start", "llm_still_waiting", "compaction"}


def append_event(eid: str, run_id: str, event: str, data: dict[str, Any]) -> dict[str, Any]:
    with SessionLocal() as db:
        row = ChatEventRow(
            engagement_id=eid, run_id=run_id, event=event,
            data_json=json.dumps(data, ensure_ascii=False),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return _encode(row)


def page_events(eid: str, after: int = 0, limit: int = 500) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(ChatEventRow).where(
                ChatEventRow.engagement_id == eid, ChatEventRow.id > after,
            ).order_by(ChatEventRow.id).limit(min(1000, max(1, limit)))
        ).all()
        return [_encode(row) for row in rows]


def _encode(row: ChatEventRow) -> dict[str, Any]:
    return {
        "id": row.id, "run_id": row.run_id, "event": row.event,
        "data": json.loads(row.data_json), "created_at": row.created_at.isoformat(),
    }


def record_answer(eid: str, question_id: str, answer: str) -> None:
    with SessionLocal() as db:
        rows = db.scalars(select(ChatEventRow).where(
            ChatEventRow.engagement_id == eid, ChatEventRow.event == "question",
        ).order_by(ChatEventRow.id.desc())).all()
        for row in rows:
            if json.loads(row.data_json).get("id") == question_id:
                append_event(eid, row.run_id, "question_answer", {"id": question_id, "answer": answer})
                return
