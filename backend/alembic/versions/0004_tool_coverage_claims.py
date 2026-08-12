"""Per-asset claims on tool_coverage — parallel-agent safety, advisory only.

Revision ID: 0004_tool_coverage_claims
Revises: 0003_exploit_candidates
Create Date: 2026-08-12
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_tool_coverage_claims"
down_revision: Union[str, None] = "0003_exploit_candidates"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "tool_coverage",
        sa.Column("claimed_by", sa.String(length=12), nullable=False, server_default=""),
    )
    op.add_column(
        "tool_coverage",
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tool_coverage", "claimed_at")
    op.drop_column("tool_coverage", "claimed_by")
