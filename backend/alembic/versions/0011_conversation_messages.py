"""Server-side Commander conversation threads.

Persist chat per engagement so the CLI and the dashboard share one thread
(history no longer lives only in the request body).

Revision ID: 0011_conversation_messages
Revises: 0010_target_bans
Create Date: 2026-08-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011_conversation_messages"
down_revision: Union[str, None] = "0010_target_bans"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "conversation_messages",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "engagement_id",
            sa.String(length=12),
            sa.ForeignKey("engagements.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("conversation_messages")
