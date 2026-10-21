"""Durable GUI chat transcript.

Revision ID: 0024_chat_events
Revises: 0023_widen_engagement_id
"""
import sqlalchemy as sa
from alembic import op

revision = "0024_chat_events"
down_revision = "0023_widen_engagement_id"
branch_labels = None
depends_on = None


def upgrade():
    if "chat_events" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "chat_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("engagement_id", sa.String(32), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_id", sa.String(32), nullable=False),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("data_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_chat_events_engagement_cursor", "chat_events", ["engagement_id", "id"])


def downgrade():
    op.drop_table("chat_events")
