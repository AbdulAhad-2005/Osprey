"""Durable scan-run history (engine / surface-expansion runs).

Revision ID: 0006_scan_runs
Revises: 0005_exploit_chains
Create Date: 2026-08-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_scan_runs"
down_revision: Union[str, None] = "0005_exploit_chains"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.String(length=24), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("kind", sa.String(length=32), nullable=False, server_default="expansion"),
        sa.Column("label", sa.String(length=256), nullable=False, server_default=""),
        sa.Column("target", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="queued"),
        sa.Column("max_passes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("include_low_confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("progress", sa.Text(), nullable=False, server_default=""),
        sa.Column("results_log_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("result_json", sa.Text(), nullable=False, server_default=""),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_runs_engagement", "scan_runs", ["engagement_id"])
    op.create_index("ix_scan_runs_status", "scan_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_scan_runs_status", table_name="scan_runs")
    op.drop_index("ix_scan_runs_engagement", table_name="scan_runs")
    op.drop_table("scan_runs")
