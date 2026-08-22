"""Durable WAF/rate-limit ban cooldowns.

The rate governor's ban cooldown can be ~10 minutes; before this it lived only in
an in-process dict, so a restart wiped active cooldowns and the platform would
immediately re-hammer a target that just blocked us. Persist the wall-clock
expiry so still-active cooldowns are rehydrated at startup.

Revision ID: 0010_target_bans
Revises: 0009_context_snapshots
Create Date: 2026-08-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010_target_bans"
down_revision: Union[str, None] = "0009_context_snapshots"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "target_bans",
        sa.Column("engagement_id", sa.String(length=12), primary_key=True),
        sa.Column("target", sa.String(length=512), primary_key=True),
        sa.Column("ban_until_epoch", sa.Float(), nullable=False, server_default="0"),
        sa.Column("fingerprint", sa.String(length=120), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("target_bans")
