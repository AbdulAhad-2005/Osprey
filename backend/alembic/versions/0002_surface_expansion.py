"""Surface expansion engine — BFS-to-fixpoint recon loop tracking.

Revision ID: 0002_surface_expansion
Revises: 0001_baseline
Create Date: 2026-08-12
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_surface_expansion"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "surface_expansion",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("last_pass_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_new_nodes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_new_edges", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("consecutive_zero_passes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_passes", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", name="uq_surface_expansion_engagement"),
    )


def downgrade() -> None:
    op.drop_table("surface_expansion")
