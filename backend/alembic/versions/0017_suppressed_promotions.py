"""Suppressed-promotion audit trail — plans/harness/04-learning-fp-cache.md
Step 4: a promotion an FP-cache pattern suppressed stays visible, never a
silent drop.

Revision ID: 0017_suppressed_promotions
Revises: 0016_exploit_candidate_observation_id
Create Date: 2026-09-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017_suppressed_promotions"
down_revision: Union[str, None] = "0016_exploit_candidate_observation_id"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "suppressed_promotions",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("observation_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("pattern_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("title", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "suppressed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_suppressed_promotions_engagement", "suppressed_promotions", ["engagement_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_suppressed_promotions_engagement", table_name="suppressed_promotions")
    op.drop_table("suppressed_promotions")
