from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from osprey.db.base import Base


class AuditEntryRow(Base):
    """Append-only, durable record of one completed tool execution."""

    __tablename__ = "audit_entries"
    __table_args__ = (
        Index("ix_audit_entries_engagement_time", "engagement_id", "created_at"),
        Index("ix_audit_entries_tool", "tool_name"),
    )

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    run_id: Mapped[str] = mapped_column(String(12), nullable=False, default="")
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    command: Mapped[str] = mapped_column(Text, nullable=False, default="")
    success: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    returncode: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    recovery_action: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    alternative_tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
