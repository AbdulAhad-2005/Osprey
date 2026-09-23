"""Hypothesis store — plans/harness/05-world-model-and-attack-paths.md Step 4.
Active hypotheses with supporting/contradicting observation ids — cheap and
written freely (no approval gate). Distinct from a Finding's evidence_records
(Plan 03): a hypothesis is an unresolved claim the reasoner is still testing,
not something filed as a finding yet.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

import orjson
from sqlalchemy import select

from osprey.db.session import SessionLocal
from osprey.models.reasoning import HypothesisRow
from osprey.schemas.reasoning import Hypothesis, HypothesisStatus

_lock = threading.Lock()


def _decode_ids(raw: str) -> list[str]:
    try:
        data = orjson.loads(raw or "[]")
        return [str(x) for x in data] if isinstance(data, list) else []
    except orjson.JSONDecodeError:
        return []


def _row_to_model(row: HypothesisRow) -> Hypothesis:
    return Hypothesis(
        id=row.id, engagement_id=row.engagement_id, statement=row.statement,
        status=HypothesisStatus(row.status),
        supporting_observation_ids=_decode_ids(row.supporting_observation_ids_json),
        contradicting_observation_ids=_decode_ids(row.contradicting_observation_ids_json),
        created_at=row.created_at, updated_at=row.updated_at,
    )


def raise_hypothesis(
    engagement_id: str, *, statement: str, supporting_observation_ids: list[str] | None = None,
) -> Hypothesis:
    eid = (engagement_id or "").strip()
    if not eid:
        raise ValueError("engagement_id required")
    if not (statement or "").strip():
        raise ValueError("statement required")
    now = datetime.now(timezone.utc)
    supporting = list(supporting_observation_ids or [])
    row = HypothesisRow(
        id=uuid.uuid4().hex[:12], engagement_id=eid, statement=statement.strip(),
        status=HypothesisStatus.ACTIVE.value,
        supporting_observation_ids_json=orjson.dumps(supporting).decode(),
        contradicting_observation_ids_json="[]",
        created_at=now, updated_at=now,
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


def add_evidence(
    hypothesis_id: str, *, observation_id: str, supports: bool,
) -> Hypothesis | None:
    """Attach a supporting or contradicting observation — this is how a
    hypothesis's evidentiary basis grows in either direction, unlike a
    Finding's confidence, which only ever comes from confidence_for."""
    with _lock:
        db = SessionLocal()
        try:
            row = db.get(HypothesisRow, hypothesis_id)
            if row is None:
                return None
            field = "supporting_observation_ids_json" if supports else "contradicting_observation_ids_json"
            ids = _decode_ids(getattr(row, field))
            if observation_id not in ids:
                ids.append(observation_id)
                setattr(row, field, orjson.dumps(ids).decode())
                row.updated_at = datetime.now(timezone.utc)
                db.commit()
                db.refresh(row)
            return _row_to_model(row)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


def resolve(hypothesis_id: str, *, status: HypothesisStatus) -> Hypothesis | None:
    if status == HypothesisStatus.ACTIVE:
        raise ValueError("resolve() sets a terminal status (confirmed/refuted), not active")
    with _lock:
        db = SessionLocal()
        try:
            row = db.get(HypothesisRow, hypothesis_id)
            if row is None:
                return None
            row.status = status.value
            row.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(row)
            return _row_to_model(row)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


def list_active(engagement_id: str, *, limit: int = 200) -> list[Hypothesis]:
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    with _lock:
        db = SessionLocal()
        try:
            rows = list(
                db.scalars(
                    select(HypothesisRow)
                    .where(HypothesisRow.engagement_id == eid, HypothesisRow.status == HypothesisStatus.ACTIVE.value)
                    .order_by(HypothesisRow.updated_at.desc())
                    .limit(limit)
                ).all()
            )
        finally:
            db.close()
    return [_row_to_model(r) for r in rows]


def list_for_engagement(engagement_id: str, *, limit: int = 500) -> list[Hypothesis]:
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    with _lock:
        db = SessionLocal()
        try:
            rows = list(
                db.scalars(
                    select(HypothesisRow)
                    .where(HypothesisRow.engagement_id == eid)
                    .order_by(HypothesisRow.updated_at.desc())
                    .limit(limit)
                ).all()
            )
        finally:
            db.close()
    return [_row_to_model(r) for r in rows]
