"""tool_coverage becomes an append-only event log.

Drops the (engagement_id, tool_name, asset) unique constraint that forced
overwrite-only state, and drops the in-flight claim columns (claims are now a
transient in-process concern, not durable state). Existing rows are preserved
and simply become the most-recent event per key.

Revision ID: 0007_tool_coverage_event_log
Revises: 0006_scan_runs
Create Date: 2026-08-18
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0007_tool_coverage_event_log"
down_revision: Union[str, None] = "0006_scan_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_tool_coverage_engagement_tool_asset",
        "tool_coverage",
        type_="unique",
    )
    op.create_index(
        "ix_tool_coverage_eng_tool_asset",
        "tool_coverage",
        ["engagement_id", "tool_name", "asset"],
    )
    op.drop_column("tool_coverage", "claimed_at")
    op.drop_column("tool_coverage", "claimed_by")


def downgrade() -> None:
    import sqlalchemy as sa

    op.add_column(
        "tool_coverage",
        sa.Column("claimed_by", sa.String(length=12), nullable=False, server_default=""),
    )
    op.add_column(
        "tool_coverage",
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.drop_index("ix_tool_coverage_eng_tool_asset", table_name="tool_coverage")
    op.create_unique_constraint(
        "uq_tool_coverage_engagement_tool_asset",
        "tool_coverage",
        ["engagement_id", "tool_name", "asset"],
    )
