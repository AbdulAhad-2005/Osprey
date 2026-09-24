from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from osprey.db.base import Base


class SuppressedPromotionRow(Base):
    """Audit trail for a promotion an FP-cache pattern suppressed — plans/
    harness/04-learning-fp-cache.md Step 4: visible, never a silent drop."""

    __tablename__ = "suppressed_promotions"
    __table_args__ = (
        Index("ix_suppressed_promotions_engagement", "engagement_id"),
    )

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    observation_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    pattern_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    title: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    suppressed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
