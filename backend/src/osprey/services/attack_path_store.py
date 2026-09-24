"""Attack-path store — plans/harness/05-world-model-and-attack-paths.md Step 3+5.

Durable (Postgres/SQLite via Alembic, not in-memory). Every write is a single
locked transaction — the same atomicity guarantee ``findings_store``/
``observation_store`` provide, so a subagent's ``advance``/``attach_evidence``
is visible to another subagent's next read (Step 5's concurrency requirement).
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

import orjson
from sqlalchemy import select

from osprey.db.session import SessionLocal
from osprey.models.attack_path import AttackPathRow
from osprey.schemas.attack_path import AttackPath, AttackPathStatus, AttackPathStep

_lock = threading.Lock()


def _row_to_model(row: AttackPathRow) -> AttackPath:
    steps_raw = orjson.loads(row.steps_json or "[]")
    return AttackPath(
        id=row.id,
        engagement_id=row.engagement_id,
        title=row.title,
        steps=[AttackPathStep.model_validate(s) for s in steps_raw],
        status=AttackPathStatus(row.status),
        finding_id=row.finding_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def propose(engagement_id: str, *, title: str, steps: list[AttackPathStep]) -> AttackPath:
    eid = (engagement_id or "").strip()
    if not eid:
        raise ValueError("engagement_id required")
    if not (title or "").strip():
        raise ValueError("title required")
    if not steps:
        raise ValueError("an attack path needs at least one step")
    now = datetime.now(timezone.utc)
    row = AttackPathRow(
        id=uuid.uuid4().hex[:12],
        engagement_id=eid,
        title=title.strip()[:500],
        steps_json=orjson.dumps([s.model_dump(mode="json") for s in steps]).decode(),
        status=AttackPathStatus.HYPOTHESIZED.value,
        created_at=now,
        updated_at=now,
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


def get(path_id: str) -> AttackPath | None:
    with _lock:
        db = SessionLocal()
        try:
            row = db.get(AttackPathRow, path_id)
            return _row_to_model(row) if row is not None else None
        finally:
            db.close()


def advance(
    path_id: str,
    *,
    status: AttackPathStatus | None = None,
    append_step: AttackPathStep | None = None,
    finding_id: str = "",
) -> AttackPath | None:
    """Move a path forward: append a new hop, and/or change its status.
    ``finding_id`` is set once a controlled PoC validates the chain."""
    with _lock:
        db = SessionLocal()
        try:
            row = db.get(AttackPathRow, path_id)
            if row is None:
                return None
            if append_step is not None:
                steps = orjson.loads(row.steps_json or "[]")
                steps.append(append_step.model_dump(mode="json"))
                row.steps_json = orjson.dumps(steps).decode()
            if status is not None:
                row.status = status.value
            if finding_id:
                row.finding_id = finding_id
            row.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(row)
            return _row_to_model(row)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


def attach_evidence(path_id: str, *, observation_id: str, rationale: str = "") -> AttackPath | None:
    """Convenience over ``advance``: append an OBSERVATION step citing new
    evidence for the current end of the chain."""
    from osprey.schemas.attack_path import AttackPathStepKind

    return advance(
        path_id,
        append_step=AttackPathStep(
            kind=AttackPathStepKind.OBSERVATION, ref_id=observation_id, rationale=rationale,
        ),
    )


def list_active(engagement_id: str, *, limit: int = 200) -> list[AttackPath]:
    """hypothesized/investigating paths — the ones still worth pursuing."""
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    with _lock:
        db = SessionLocal()
        try:
            rows = list(
                db.scalars(
                    select(AttackPathRow)
                    .where(
                        AttackPathRow.engagement_id == eid,
                        AttackPathRow.status.in_(
                            [AttackPathStatus.HYPOTHESIZED.value, AttackPathStatus.INVESTIGATING.value]
                        ),
                    )
                    .order_by(AttackPathRow.updated_at.desc())
                    .limit(limit)
                ).all()
            )
        finally:
            db.close()
    return [_row_to_model(r) for r in rows]


def list_for_engagement(engagement_id: str, *, limit: int = 500) -> list[AttackPath]:
    eid = (engagement_id or "").strip()
    if not eid:
        return []
    with _lock:
        db = SessionLocal()
        try:
            rows = list(
                db.scalars(
                    select(AttackPathRow)
                    .where(AttackPathRow.engagement_id == eid)
                    .order_by(AttackPathRow.updated_at.desc())
                    .limit(limit)
                ).all()
            )
        finally:
            db.close()
    return [_row_to_model(r) for r in rows]
