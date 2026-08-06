"""Create recovery_observations table (shadow-mode execution recovery evidence).

Revision ID: 007_recovery_observations
Revises: 006_finding_grade_severity
Create Date: 2026-08-05
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "007_recovery_observations"
down_revision: Union[str, None] = "006_finding_grade_severity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "recovery_observations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("asset", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("error_type", sa.String(length=64), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("shadow_strategy", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("llm_subsequent_tool", sa.String(length=128), nullable=True),
        sa.Column("llm_subsequent_success", sa.Integer(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_recovery_obs_engagement", "recovery_observations", ["engagement_id"], unique=False)
    op.create_index(
        "ix_recovery_obs_tool_error", "recovery_observations", ["tool_name", "error_type"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_recovery_obs_tool_error", table_name="recovery_observations")
    op.drop_index("ix_recovery_obs_engagement", table_name="recovery_observations")
    op.drop_table("recovery_observations")
