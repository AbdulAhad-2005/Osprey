"""Attack paths, questions, hypotheses — plans/harness/05-world-model-and-
attack-paths.md Steps 3-5.

Revision ID: 0019_attack_paths_and_reasoning
Revises: 0018_graph_observation_provenance
Create Date: 2026-09-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0019_attack_paths_and_reasoning"
down_revision: Union[str, None] = "0018_graph_observation_provenance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_paths",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("title", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("steps_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="hypothesized"),
        sa.Column("finding_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_attack_paths_engagement", "attack_paths", ["engagement_id"], unique=False)
    op.create_index(
        "ix_attack_paths_engagement_status", "attack_paths", ["engagement_id", "status"], unique=False
    )

    op.create_table(
        "questions",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("text", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
        sa.Column("raised_by", sa.String(length=32), nullable=False, server_default="llm"),
        sa.Column("related_asset_id", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("answer", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_questions_engagement", "questions", ["engagement_id"], unique=False)
    op.create_index(
        "ix_questions_engagement_status", "questions", ["engagement_id", "status"], unique=False
    )

    op.create_table(
        "hypotheses",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("statement", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("supporting_observation_ids_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("contradicting_observation_ids_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_hypotheses_engagement", "hypotheses", ["engagement_id"], unique=False)
    op.create_index(
        "ix_hypotheses_engagement_status", "hypotheses", ["engagement_id", "status"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_hypotheses_engagement_status", table_name="hypotheses")
    op.drop_index("ix_hypotheses_engagement", table_name="hypotheses")
    op.drop_table("hypotheses")

    op.drop_index("ix_questions_engagement_status", table_name="questions")
    op.drop_index("ix_questions_engagement", table_name="questions")
    op.drop_table("questions")

    op.drop_index("ix_attack_paths_engagement_status", table_name="attack_paths")
    op.drop_index("ix_attack_paths_engagement", table_name="attack_paths")
    op.drop_table("attack_paths")
