"""Create soft tool_coverage table (M4).

Revision ID: 004_tool_coverage
Revises: 003_finding_flexible_fields
Create Date: 2026-07-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "004_tool_coverage"
down_revision: Union[str, None] = "003_finding_flexible_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tool_coverage",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("asset", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("success", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("completed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "engagement_id",
            "tool_name",
            "asset",
            name="uq_tool_coverage_engagement_tool_asset",
        ),
    )
    op.create_index("ix_tool_coverage_engagement", "tool_coverage", ["engagement_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_tool_coverage_engagement", table_name="tool_coverage")
    op.drop_table("tool_coverage")
