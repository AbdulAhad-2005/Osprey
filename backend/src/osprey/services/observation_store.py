"""Observation store — plans/harness/02-evidence-and-observation-layer.md Step 2.

Idempotent on ``signature``: a re-scan or a second tool corroborating the same
fact merges into the existing canonical row (bumps ``occurrence_count`` /
``last_seen_at``, appends an occurrence) instead of inserting a duplicate —
same dedup shape as ``findings_store.add_many_result``, deliberately not
reinvented. Writes are SAVEPOINT-scoped so a concurrent writer's fingerprint
collision (two subagents observing the same host in parallel) only retries
that one insert, never rolls back the whole batch.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

import orjson
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from osprey.db.session import SessionLocal
from osprey.models.observation import ObservationOccurrenceRow, ObservationRow
from osprey.schemas.observation import Observation, ObservationType, observation_signature


def _decode_details(raw: str) -> dict[str, Any]:
    try:
        data = orjson.loads(raw or "{}")
        return data if isinstance(data, dict) else {}
    except orjson.JSONDecodeError:
        return {}


def _decode_tags(raw: str) -> list[str]:
    try:
        data = orjson.loads(raw or "[]")
        return [str(t) for t in data] if isinstance(data, list) else []
    except orjson.JSONDecodeError:
        return []


def _row_to_observation(row: ObservationRow) -> Observation:
    return Observation(
        id=row.id,
        engagement_id=row.engagement_id,
        run_id=row.run_id,
        evidence_id=row.evidence_id,
        type=ObservationType(row.type),
        details=_decode_details(row.details_json),
        confidence=row.confidence,
        source_tool=row.source_tool,
        target=row.target,
        extracted_by=row.extracted_by,  # type: ignore[arg-type]
        tags=_decode_tags(row.tags_json),
        signature=row.signature,
        created_at=row.first_seen_at,
        occurrence_count=row.occurrence_count,
        last_seen_at=row.last_seen_at,
    )


def _observation_to_row(obs: Observation, *, signature: str, now: datetime) -> ObservationRow:
    return ObservationRow(
        id=obs.id or uuid.uuid4().hex[:12],
        engagement_id=obs.engagement_id or "",
        run_id=obs.run_id or "",
        evidence_id=obs.evidence_id or "",
        type=obs.type.value,
        signature=signature,
        target=(obs.target or "")[:512],
        source_tool=(obs.source_tool or "")[:128],
        extracted_by=obs.extracted_by.value,
        confidence=obs.confidence or "observed",
        details_json=orjson.dumps(obs.details or {}).decode(),
        tags_json=orjson.dumps(obs.tags or []).decode(),
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
    )


def _occurrence_row(observation_id: str, obs: Observation, now: datetime) -> ObservationOccurrenceRow:
    return ObservationOccurrenceRow(
        observation_id=observation_id,
        engagement_id=obs.engagement_id or "",
        run_id=obs.run_id or "",
        evidence_id=obs.evidence_id or "",
        source_tool=(obs.source_tool or "")[:128],
        extracted_by=obs.extracted_by.value,
        created_at=now,
    )


@dataclass
class ObservationWriteResult:
    observations: list[Observation] = field(default_factory=list)
    stored: int = 0
    merged: int = 0


class ObservationStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def record(self, observation: Observation) -> Observation:
        return self.record_many([observation]).observations[0]

    def record_many(self, observations: Iterable[Observation]) -> ObservationWriteResult:
        items = list(observations)
        if not items:
            return ObservationWriteResult()
        for obs in items:
            if not (obs.engagement_id or "").strip():
                raise ValueError("Cannot persist observation without engagement_id.")

        result: list[Observation] = []
        appended: set[str] = set()
        stored = 0
        merged = 0
        with self._lock:
            db = SessionLocal()
            try:
                now = datetime.now(timezone.utc)
                batch_canonical: dict[tuple[str, str], ObservationRow] = {}
                for obs in items:
                    sig = observation_signature(obs)
                    key = (obs.engagement_id or "", sig)
                    existing = batch_canonical.get(key)
                    if existing is None:
                        existing = db.scalars(
                            select(ObservationRow).where(
                                ObservationRow.engagement_id == (obs.engagement_id or ""),
                                ObservationRow.signature == sig,
                            )
                        ).first()
                    if existing is not None:
                        self._merge_occurrence(db, existing, obs, now)
                        batch_canonical[key] = existing
                        if existing.id not in appended:
                            result.append(_row_to_observation(existing))
                            appended.add(existing.id)
                        merged += 1
                        continue

                    row = _observation_to_row(obs, signature=sig, now=now)
                    try:
                        with db.begin_nested():
                            db.add(row)
                            db.flush()
                            db.add(_occurrence_row(row.id, obs, now))
                            db.flush()
                    except IntegrityError:
                        existing = db.scalars(
                            select(ObservationRow).where(
                                ObservationRow.engagement_id == (obs.engagement_id or ""),
                                ObservationRow.signature == sig,
                            )
                        ).first()
                        if existing is None:
                            raise
                        self._merge_occurrence(db, existing, obs, now)
                        batch_canonical[key] = existing
                        if existing.id not in appended:
                            result.append(_row_to_observation(existing))
                            appended.add(existing.id)
                        merged += 1
                        continue
                    batch_canonical[key] = row
                    result.append(_row_to_observation(row))
                    appended.add(row.id)
                    stored += 1
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        return ObservationWriteResult(observations=result, stored=stored, merged=merged)

    @staticmethod
    def _merge_occurrence(db, existing: ObservationRow, obs: Observation, now: datetime) -> None:
        existing.occurrence_count = int(existing.occurrence_count or 1) + 1
        existing.last_seen_at = now
        if obs.evidence_id:
            existing.evidence_id = obs.evidence_id
        if obs.source_tool:
            existing.source_tool = obs.source_tool
        db.add(_occurrence_row(existing.id, obs, now))

    def list_for_engagement(self, engagement_id: str, *, limit: int = 2000) -> list[Observation]:
        eid = (engagement_id or "").strip()
        if not eid:
            return []
        with self._lock:
            db = SessionLocal()
            try:
                stmt = (
                    select(ObservationRow)
                    .where(ObservationRow.engagement_id == eid)
                    .order_by(ObservationRow.last_seen_at.desc())
                    .limit(max(1, min(int(limit), 10_000)))
                )
                rows = list(db.scalars(stmt).all())
            finally:
                db.close()
        return [_row_to_observation(r) for r in rows]

    def list_by_type(
        self, engagement_id: str, obs_type: ObservationType | str, *, limit: int = 2000
    ) -> list[Observation]:
        eid = (engagement_id or "").strip()
        if not eid:
            return []
        type_val = obs_type.value if isinstance(obs_type, ObservationType) else str(obs_type)
        with self._lock:
            db = SessionLocal()
            try:
                stmt = (
                    select(ObservationRow)
                    .where(
                        ObservationRow.engagement_id == eid,
                        ObservationRow.type == type_val,
                    )
                    .order_by(ObservationRow.last_seen_at.desc())
                    .limit(max(1, min(int(limit), 10_000)))
                )
                rows = list(db.scalars(stmt).all())
            finally:
                db.close()
        return [_row_to_observation(r) for r in rows]

    def list_by_target(self, engagement_id: str, target: str, *, limit: int = 2000) -> list[Observation]:
        eid = (engagement_id or "").strip()
        tgt = (target or "").strip()
        if not eid or not tgt:
            return []
        with self._lock:
            db = SessionLocal()
            try:
                stmt = (
                    select(ObservationRow)
                    .where(
                        ObservationRow.engagement_id == eid,
                        ObservationRow.target == tgt,
                    )
                    .order_by(ObservationRow.last_seen_at.desc())
                    .limit(max(1, min(int(limit), 10_000)))
                )
                rows = list(db.scalars(stmt).all())
            finally:
                db.close()
        return [_row_to_observation(r) for r in rows]

    def distinct_source_tools(self, observation_id: str) -> list[str]:
        """Every distinct source_tool that has independently reported this
        canonical observation — the corroboration signal ``confidence_for``
        needs (plans/harness/03-earned-finding-pipeline.md)."""
        oid = (observation_id or "").strip()
        if not oid:
            return []
        with self._lock:
            db = SessionLocal()
            try:
                rows = db.scalars(
                    select(ObservationOccurrenceRow.source_tool).where(
                        ObservationOccurrenceRow.observation_id == oid
                    )
                ).all()
            finally:
                db.close()
        return sorted({str(r) for r in rows if r})

    def get(self, observation_id: str) -> Observation | None:
        oid = (observation_id or "").strip()
        if not oid:
            return None
        with self._lock:
            db = SessionLocal()
            try:
                row = db.get(ObservationRow, oid)
                return _row_to_observation(row) if row is not None else None
            finally:
                db.close()


_store: ObservationStore | None = None
_store_lock = threading.Lock()


def get_observation_store() -> ObservationStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = ObservationStore()
    return _store
