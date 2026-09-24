from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from osprey.db.base import Base


class AttackPathRow(Base):
    """An attack path — plans/harness/05-world-model-and-attack-paths.md Step 3."""

    __tablename__ = "attack_paths"
    __table_args__ = (
        Index("ix_attack_paths_engagement", "engagement_id"),
        Index("ix_attack_paths_engagement_status", "engagement_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    steps_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="hypothesized")
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
