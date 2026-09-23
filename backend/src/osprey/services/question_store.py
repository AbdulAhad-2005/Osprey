"""Question store — plans/harness/05-world-model-and-attack-paths.md Step 4.
Open questions are cheap and written freely (no approval gate)."""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from osprey.db.session import SessionLocal
from osprey.models.reasoning import QuestionRow
from osprey.schemas.reasoning import Question, QuestionStatus

_lock = threading.Lock()


def _row_to_model(row: QuestionRow) -> Question:
    return Question(
        id=row.id, engagement_id=row.engagement_id, text=row.text,
        status=QuestionStatus(row.status), raised_by=row.raised_by,
        related_asset_id=row.related_asset_id, answer=row.answer,
        created_at=row.created_at, updated_at=row.updated_at,
    )


def raise_question(
    engagement_id: str, *, text: str, raised_by: str = "llm", related_asset_id: str = "",
) -> Question:
    eid = (engagement_id or "").strip()
    if not eid:
        raise ValueError("engagement_id required")
    if not (text or "").strip():
        raise ValueError("text required")
    now = datetime.now(timezone.utc)
    row = QuestionRow(
        id=uuid.uuid4().hex[:12], engagement_id=eid, text=text.strip(),
        status=QuestionStatus.OPEN.value, raised_by=(raised_by or "llm").strip(),
        related_asset_id=(related_asset_id or "").strip(), created_at=now, updated_at=now,
    )
    with _lock:
        db = SessionLocal()
        try:
            db.add(row)
            db.commit()
            db.refresh(row)
        finally:
            db.close()
    return _row_to_model(row)


def answer(question_id: str, *, answer_text: str) -> Question | None:
    with _lock:
        db = SessionLocal()
        try:
            row = db.get(QuestionRow, question_id)
            if row is None:
                return None
            row.answer = answer_text
            row.status = QuestionStatus.ANSWERED.value
            row.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(row)
            return _row_to_model(row)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


def dismiss(question_id: str) -> Question | None:
    with _lock:
        db = SessionLocal()
        try:
            row = db.get(QuestionRow, question_id)
            if row is None:
                return None
            row.status = QuestionStatus.DISMISSED.value
            row.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(row)
            return _row_to_model(row)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


def list_open(engagement_id: str, *, limit: int = 200) -> list[Question]:
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    with _lock:
        db = SessionLocal()
        try:
            rows = list(
                db.scalars(
                    select(QuestionRow)
                    .where(QuestionRow.engagement_id == eid, QuestionRow.status == QuestionStatus.OPEN.value)
                    .order_by(QuestionRow.created_at.desc())
                    .limit(limit)
                ).all()
            )
        finally:
            db.close()
    return [_row_to_model(r) for r in rows]


def list_for_engagement(engagement_id: str, *, limit: int = 500) -> list[Question]:
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    with _lock:
        db = SessionLocal()
        try:
            rows = list(
                db.scalars(
                    select(QuestionRow)
                    .where(QuestionRow.engagement_id == eid)
                    .order_by(QuestionRow.created_at.desc())
                    .limit(limit)
                ).all()
            )
        finally:
            db.close()
    return [_row_to_model(r) for r in rows]
