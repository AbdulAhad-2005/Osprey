"""Evidence + Observation layer.

plans/harness/02-evidence-and-observation-layer.md Steps 1-2: promote raw
tool output into a queryable ``evidence`` row, and add ``observations`` as the
only thing structural extraction (parsers) is allowed to produce — never a
``Finding``. Findings become earned outputs of the Plan 03 pipeline instead.

Revision ID: 0014_evidence_and_observations
Revises: 0013_drop_exploit_chains
Create Date: 2026-09-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014_evidence_and_observations"
down_revision: Union[str, None] = "0013_drop_exploit_chains"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("tool_name", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("target", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("command", sa.Text(), nullable=False, server_default=""),
        sa.Column("stdout_path", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("stderr_path", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("exit_code", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_engagement", "evidence", ["engagement_id"], unique=False)
    op.create_index(
        "ix_evidence_engagement_run", "evidence", ["engagement_id", "run_id"], unique=False
    )
    op.create_index("ix_evidence_tool", "evidence", ["tool_name"], unique=False)

    op.create_table(
        "observations",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("evidence_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("target", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("source_tool", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("extracted_by", sa.String(length=16), nullable=False, server_default="parser"),
        sa.Column("confidence", sa.String(length=16), nullable=False, server_default="observed"),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("tags_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "engagement_id", "signature", name="uq_observations_engagement_signature"
        ),
    )
    op.create_index(
        "ix_observations_engagement_type", "observations", ["engagement_id", "type"], unique=False
    )
    op.create_index(
        "ix_observations_engagement_target",
        "observations",
        ["engagement_id", "target"],
        unique=False,
    )
    op.create_index("ix_observations_evidence", "observations", ["evidence_id"], unique=False)
    op.create_index("ix_observations_engagement", "observations", ["engagement_id"], unique=False)

    op.create_table(
        "observation_occurrences",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("observation_id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("evidence_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("source_tool", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("extracted_by", sa.String(length=16), nullable=False, server_default="parser"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(["observation_id"], ["observations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_observation_occurrences_observation",
        "observation_occurrences",
        ["observation_id"],
        unique=False,
    )
    op.create_index(
        "ix_observation_occurrences_engagement",
        "observation_occurrences",
        ["engagement_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_observation_occurrences_engagement", table_name="observation_occurrences")
    op.drop_index("ix_observation_occurrences_observation", table_name="observation_occurrences")
    op.drop_table("observation_occurrences")

    op.drop_index("ix_observations_engagement", table_name="observations")
    op.drop_index("ix_observations_evidence", table_name="observations")
    op.drop_index("ix_observations_engagement_target", table_name="observations")
    op.drop_index("ix_observations_engagement_type", table_name="observations")
    op.drop_table("observations")

    op.drop_index("ix_evidence_tool", table_name="evidence")
    op.drop_index("ix_evidence_engagement_run", table_name="evidence")
    op.drop_index("ix_evidence_engagement", table_name="evidence")
    op.drop_table("evidence")
