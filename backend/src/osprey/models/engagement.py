from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from osprey.db.base import Base


class EngagementRow(Base):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="created")
    rules_of_engagement_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tools_executed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
