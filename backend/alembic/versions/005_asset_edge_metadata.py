"""Add metadata_json, run_id, source_tool, created_at to asset_edges — graph edges
gain the same property-bag richness nodes already had, plus provenance (who
created this edge, when, from which run) so it's queryable, not just inferrable.

Revision ID: 005_asset_edge_metadata
Revises: 004_tool_coverage
Create Date: 2026-07-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "005_asset_edge_metadata"
down_revision: Union[str, None] = "004_tool_coverage"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "asset_edges",
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "asset_edges",
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
    )
    op.add_column(
        "asset_edges",
        sa.Column("source_tool", sa.String(length=128), nullable=False, server_default=""),
    )
    op.add_column(
        "asset_edges",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("asset_edges", "created_at")
    op.drop_column("asset_edges", "source_tool")
    op.drop_column("asset_edges", "run_id")
    op.drop_column("asset_edges", "metadata_json")
