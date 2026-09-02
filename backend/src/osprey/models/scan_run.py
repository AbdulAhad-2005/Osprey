from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from osprey.db.base import Base


class ScanRunRow(Base):
    """Durable record of an engine (surface-expansion) scan run.

    Background jobs themselves are process-local (an asyncio task that dies on
    restart), but the *history* of what was scanned, when, its status, live
    results log and final report should survive a backend restart so scan
    history is queryable (dashboard / audit) instead of vanishing with the
    in-memory job store. One row per engine run, keyed by the job id.
    """

    __tablename__ = "scan_runs"
    __table_args__ = (
        Index("ix_scan_runs_engagement", "engagement_id"),
        Index("ix_scan_runs_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(24), primary_key=True)  # job_id
    engagement_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    run_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="expansion")
    label: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    target: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    max_passes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    include_low_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # JSON-serialized (Text, matching the rest of the schema — not native JSONB).
    results_log_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    result_json: Mapped[str] = mapped_column(Text, nullable=False, default="")
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
