"""Durable append-only tool execution audit log.

Revision ID: 0014_durable_audit_entries
Revises: 0013_drop_exploit_chains
Create Date: 2026-09-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_durable_audit_entries"
down_revision: str | None = "0013_drop_exploit_chains"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "audit_entries" not in tables:
        op.create_table(
            "audit_entries",
            sa.Column("id", sa.String(length=16), nullable=False),
            sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("tool_name", sa.String(length=128), nullable=False),
            sa.Column("target", sa.String(length=512), nullable=False, server_default=""),
            sa.Column("command", sa.Text(), nullable=False, server_default=""),
            sa.Column("success", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("returncode", sa.Integer(), nullable=True),
            sa.Column("duration_seconds", sa.Float(), nullable=False, server_default="0"),
            sa.Column("error", sa.Text(), nullable=False, server_default=""),
            sa.Column("recovery_action", sa.String(length=128), nullable=False, server_default=""),
            sa.Column("alternative_tool", sa.String(length=128), nullable=False, server_default=""),
            sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_audit_entries_engagement_time",
            "audit_entries",
            ["engagement_id", "created_at"],
        )
        op.create_index("ix_audit_entries_tool", "audit_entries", ["tool_name"])

    scan_columns = {
        column["name"] for column in inspector.get_columns("scan_runs")
    }
    with op.batch_alter_table("scan_runs") as batch_op:
        if "request_json" not in scan_columns:
            batch_op.add_column(
                sa.Column("request_json", sa.Text(), nullable=False, server_default="{}")
            )
        if "command_preview" not in scan_columns:
            batch_op.add_column(
                sa.Column("command_preview", sa.Text(), nullable=False, server_default="")
            )
        if "heartbeat_at" not in scan_columns:
            batch_op.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    scan_columns = {
        column["name"] for column in sa.inspect(op.get_bind()).get_columns("scan_runs")
    }
    with op.batch_alter_table("scan_runs") as batch_op:
        for name in ("heartbeat_at", "command_preview", "request_json"):
            if name in scan_columns:
                batch_op.drop_column(name)
    op.drop_index("ix_audit_entries_tool", table_name="audit_entries")
    op.drop_index("ix_audit_entries_engagement_time", table_name="audit_entries")
    op.drop_table("audit_entries")
