from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from osprey.db.base import Base


class ObservationRow(Base):
    """A canonical structural fact — one row per distinct ``signature`` per
    engagement (plans/harness/02-evidence-and-observation-layer.md Step 2).
    Repeated sightings (a re-scan, a second tool) bump ``occurrence_count`` /
    ``last_seen_at`` via ``observation_occurrences`` instead of inserting a
    duplicate row — same dedup shape as ``FindingRow``/``FindingOccurrenceRow``.
    """

    __tablename__ = "observations"
    __table_args__ = (
        UniqueConstraint(
            "engagement_id", "signature", name="uq_observations_engagement_signature"
        ),
        Index("ix_observations_engagement_type", "engagement_id", "type"),
        Index("ix_observations_engagement_target", "engagement_id", "target"),
        Index("ix_observations_evidence", "evidence_id"),
    )

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(12), nullable=False, default="", index=True)
    run_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    evidence_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    source_tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    extracted_by: Mapped[str] = mapped_column(String(16), nullable=False, default="parser")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="observed")
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    tags_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ObservationOccurrenceRow(Base):
    """One sighting of a canonical observation — full provenance, nothing
    silently dropped on merge."""

    __tablename__ = "observation_occurrences"
    __table_args__ = (
        Index("ix_observation_occurrences_observation", "observation_id"),
        Index("ix_observation_occurrences_engagement", "engagement_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observation_id: Mapped[str] = mapped_column(
        String(12), ForeignKey("observations.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    run_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    evidence_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    source_tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    extracted_by: Mapped[str] = mapped_column(String(16), nullable=False, default="parser")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
