"""Audit trail for FP-cache-suppressed promotions — plans/harness/04-learning-
fp-cache.md Step 4."""

from __future__ import annotations

import threading
import uuid

from sqlalchemy import select

from osprey.db.session import SessionLocal
from osprey.models.suppressed_promotion import SuppressedPromotionRow
from osprey.schemas.fp_cache import SuppressedPromotion

_lock = threading.Lock()


def record(
    *, engagement_id: str, observation_id: str, pattern_id: str, title: str, reason: str
) -> SuppressedPromotion:
    row = SuppressedPromotionRow(
        id=uuid.uuid4().hex[:12],
        engagement_id=engagement_id,
        observation_id=observation_id,
        pattern_id=pattern_id,
        title=title[:1024],
        reason=reason,
    )
    with _lock:
        db = SessionLocal()
        try:
            db.add(row)
            db.commit()
            db.refresh(row)
        finally:
            db.close()
    return SuppressedPromotion(
        id=row.id, engagement_id=row.engagement_id, observation_id=row.observation_id,
        pattern_id=row.pattern_id, title=row.title, reason=row.reason, suppressed_at=row.suppressed_at,
    )


def list_for_engagement(engagement_id: str, *, limit: int = 500) -> list[SuppressedPromotion]:
    with _lock:
        db = SessionLocal()
        try:
            rows = list(
                db.scalars(
                    select(SuppressedPromotionRow)
                    .where(SuppressedPromotionRow.engagement_id == engagement_id)
                    .order_by(SuppressedPromotionRow.suppressed_at.desc())
                    .limit(limit)
                ).all()
            )
        finally:
            db.close()
    return [
        SuppressedPromotion(
            id=r.id, engagement_id=r.engagement_id, observation_id=r.observation_id,
            pattern_id=r.pattern_id, title=r.title, reason=r.reason, suppressed_at=r.suppressed_at,
        )
        for r in rows
    ]
