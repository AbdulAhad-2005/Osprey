from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from osprey.db.base import Base


class QuestionRow(Base):
    """An open question — plans/harness/05-world-model-and-attack-paths.md
    Step 4. Cheap and written freely; no approval gate."""

    __tablename__ = "questions"
    __table_args__ = (
        Index("ix_questions_engagement", "engagement_id"),
        Index("ix_questions_engagement_status", "engagement_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    raised_by: Mapped[str] = mapped_column(String(32), nullable=False, default="llm")
    related_asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    answer: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class HypothesisRow(Base):
    """An active hypothesis — plans/harness/05-world-model-and-attack-paths.md
    Step 4. Supporting/contradicting observation ids let confidence-in-the-
    hypothesis move either way as evidence accumulates."""

    __tablename__ = "hypotheses"
    __table_args__ = (
        Index("ix_hypotheses_engagement", "engagement_id"),
        Index("ix_hypotheses_engagement_status", "engagement_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    statement: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    supporting_observation_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    contradicting_observation_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
