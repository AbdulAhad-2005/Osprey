from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from osprey.db.base import Base


class EvidenceRow(Base):
    """One row per tool run — the queryable promotion of stdout_index/artifacts
    (plans/harness/02-evidence-and-observation-layer.md Step 1). The full body
    stays on disk at ``stdout_path``/``stderr_path``; this row is metadata +
    pointer, cited by ``ObservationRow.evidence_id``."""

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_engagement", "engagement_id"),
        Index("ix_evidence_engagement_run", "engagement_id", "run_id"),
        Index("ix_evidence_tool", "tool_name"),
    )

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    run_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    command: Mapped[str] = mapped_column(Text, nullable=False, default="")
    stdout_path: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    stderr_path: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    exit_code: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
