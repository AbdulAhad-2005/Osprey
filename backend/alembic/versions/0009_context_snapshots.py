"""Durable per-engagement context-delta baseline.

The 'what changed since last read' signal was an in-memory dict that reset to a
full first-snapshot on every backend restart. Persist it so the delta survives.

Revision ID: 0009_context_snapshots
Revises: 0008_trgm_search_indexes
Create Date: 2026-08-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009_context_snapshots"
down_revision: Union[str, None] = "0008_trgm_search_indexes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "context_snapshots",
        sa.Column("engagement_id", sa.String(length=12), primary_key=True),
        sa.Column("nodes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ports", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("urls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ts", sa.Float(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("context_snapshots")
