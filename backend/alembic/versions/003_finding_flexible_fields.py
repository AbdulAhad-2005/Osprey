"""Create findings flexible storage columns (M2).

Revision ID: 003_finding_flexible_fields
Revises: 002_findings_graph
Create Date: 2026-07-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003_finding_flexible_fields"
down_revision: Union[str, None] = "002_findings_graph"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("tags_json", sa.Text(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "findings",
        sa.Column("extra_json", sa.Text(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "findings",
        sa.Column("raw_data", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "findings",
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("findings", "notes")
    op.drop_column("findings", "raw_data")
    op.drop_column("findings", "extra_json")
    op.drop_column("findings", "tags_json")
