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

import sqlalchemy as sa
from alembic import op

revision: str = "0007_tool_coverage_event_log"
down_revision: Union[str, None] = "0006_scan_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Batch mode is required for SQLite, which cannot ALTER constraints or
    # drop columns in place.  It is also valid on Postgres, keeping one
    # migration path for both supported databases.
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("tool_coverage")}
    unique_constraints = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("tool_coverage")
        if constraint.get("name")
    }
    indexes = {index["name"] for index in inspector.get_indexes("tool_coverage")}
    with op.batch_alter_table("tool_coverage") as batch_op:
        if "uq_tool_coverage_engagement_tool_asset" in unique_constraints:
            batch_op.drop_constraint(
                "uq_tool_coverage_engagement_tool_asset",
                type_="unique",
            )
        if "ix_tool_coverage_eng_tool_asset" not in indexes:
            batch_op.create_index(
                "ix_tool_coverage_eng_tool_asset",
                ["engagement_id", "tool_name", "asset"],
            )
        if "claimed_at" in columns:
            batch_op.drop_column("claimed_at")
        if "claimed_by" in columns:
            batch_op.drop_column("claimed_by")


def downgrade() -> None:
    with op.batch_alter_table("tool_coverage") as batch_op:
        batch_op.add_column(
            sa.Column("claimed_by", sa.String(length=12), nullable=False, server_default=""),
        )
        batch_op.add_column(
            sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        )
        batch_op.drop_index("ix_tool_coverage_eng_tool_asset")
        batch_op.create_unique_constraint(
            "uq_tool_coverage_engagement_tool_asset",
            ["engagement_id", "tool_name", "asset"],
        )
