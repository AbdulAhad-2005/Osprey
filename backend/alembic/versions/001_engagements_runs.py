"""Create engagements and runs tables (M0).

Revision ID: 001_engagements_runs
Revises:
Create Date: 2026-07-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "001_engagements_runs"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "engagements",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="created"),
        sa.Column("rules_of_engagement_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tools_executed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_engagements_target", "engagements", ["target"], unique=False)

    op.create_table(
        "runs",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_runs_engagement_id", "runs", ["engagement_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_runs_engagement_id", table_name="runs")
    op.drop_table("runs")
    op.drop_index("ix_engagements_target", table_name="engagements")
    op.drop_table("engagements")
