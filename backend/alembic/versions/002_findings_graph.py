"""Create findings, asset_nodes, asset_edges tables (M1).

Revision ID: 002_findings_graph
Revises: 001_engagements_runs
Create Date: 2026-07-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002_findings_graph"
down_revision: Union[str, None] = "001_engagements_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("phase", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("finding_type", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=1024), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.String(length=32), nullable=False, server_default="confirmed"),
        sa.Column("source_tool", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("target", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_engagement_id", "findings", ["engagement_id"], unique=False)
    op.create_index("ix_findings_run_id", "findings", ["run_id"], unique=False)
    op.create_index("ix_findings_engagement_type", "findings", ["engagement_id", "finding_type"], unique=False)
    op.create_index("ix_findings_engagement_run", "findings", ["engagement_id", "run_id"], unique=False)
    op.create_index("ix_findings_source_tool", "findings", ["source_tool"], unique=False)

    op.create_table(
        "asset_nodes",
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("id", sa.String(length=512), nullable=False),
        sa.Column("asset_type", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=1024), nullable=False),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.PrimaryKeyConstraint("engagement_id", "id"),
    )
    op.create_index(
        "ix_asset_nodes_engagement_type",
        "asset_nodes",
        ["engagement_id", "asset_type"],
        unique=False,
    )
    op.create_index(
        "ix_asset_nodes_engagement_run",
        "asset_nodes",
        ["engagement_id", "run_id"],
        unique=False,
    )

    op.create_table(
        "asset_edges",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("source_id", sa.String(length=512), nullable=False),
        sa.Column("target_id", sa.String(length=512), nullable=False),
        sa.Column("relationship", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "engagement_id",
            "source_id",
            "target_id",
            "relationship",
            name="uq_asset_edges_engagement_link",
        ),
    )
    op.create_index("ix_asset_edges_engagement", "asset_edges", ["engagement_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_asset_edges_engagement", table_name="asset_edges")
    op.drop_table("asset_edges")
    op.drop_index("ix_asset_nodes_engagement_run", table_name="asset_nodes")
    op.drop_index("ix_asset_nodes_engagement_type", table_name="asset_nodes")
    op.drop_table("asset_nodes")
    op.drop_index("ix_findings_source_tool", table_name="findings")
    op.drop_index("ix_findings_engagement_run", table_name="findings")
    op.drop_index("ix_findings_engagement_type", table_name="findings")
    op.drop_index("ix_findings_run_id", table_name="findings")
    op.drop_index("ix_findings_engagement_id", table_name="findings")
    op.drop_table("findings")
