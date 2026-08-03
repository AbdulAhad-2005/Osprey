"""Promote evidence_grade and claim_severity from extra_json to native columns.

Adds indexed columns for SQL-level filtering. Existing data is backfilled
from extra_json automatically in the upgrade step.

Revision ID: 006_finding_grade_severity
Revises: 005_asset_edge_metadata
Create Date: 2026-08-02
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "006_finding_grade_severity"
down_revision: Union[str, None] = "005_asset_edge_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "evidence_grade",
            sa.String(length=32),
            nullable=False,
            server_default="inferred",
        ),
    )
    op.add_column(
        "findings",
        sa.Column(
            "claim_severity",
            sa.String(length=32),
            nullable=False,
            server_default="none",
        ),
    )
    op.create_index(
        "ix_findings_engagement_severity",
        "findings",
        ["engagement_id", "claim_severity"],
        unique=False,
    )
    op.create_index(
        "ix_findings_engagement_grade",
        "findings",
        ["engagement_id", "evidence_grade"],
        unique=False,
    )

    # Backfill from extra_json for existing rows
    op.execute(
        """
        UPDATE findings
        SET evidence_grade = COALESCE(
            (extra_json::jsonb ->> 'evidence_grade'),
            'inferred'
        )
        WHERE evidence_grade = 'inferred'
          AND extra_json != '{}'
          AND extra_json::jsonb ? 'evidence_grade'
        """
    )
    op.execute(
        """
        UPDATE findings
        SET claim_severity = COALESCE(
            (extra_json::jsonb ->> 'claim_severity'),
            'none'
        )
        WHERE claim_severity = 'none'
          AND extra_json != '{}'
          AND extra_json::jsonb ? 'claim_severity'
        """
    )


def downgrade() -> None:
    op.drop_index("ix_findings_engagement_grade", table_name="findings")
    op.drop_index("ix_findings_engagement_severity", table_name="findings")
    op.drop_column("findings", "claim_severity")
    op.drop_column("findings", "evidence_grade")
