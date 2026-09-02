from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from osprey.db.base import Base


class ContextSnapshotRow(Base):
    """Last context-delta baseline per engagement — durable so the 'what changed
    since last read' signal survives a backend restart (was an in-memory dict
    that reset to a full first-snapshot on every restart). One row per engagement,
    upserted on each recompute.
    """

    __tablename__ = "context_snapshots"

    engagement_id: Mapped[str] = mapped_column(String(12), primary_key=True)
    nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ports: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    urls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ts: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
