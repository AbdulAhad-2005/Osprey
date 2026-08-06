"""Clean baseline schema (greenfield).

Squashes the former 001-007 ALTER-patch chain into one baseline reflecting the
current model: findings with semantic fingerprint + occurrence-vs-canonical
(``finding_occurrences``), asset nodes with provenance/grade, and the downstream
finding types. No data is preserved — this is a fresh-install baseline.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-08-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "engagements",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=64), nullable=False, server_default="created"),
        sa.Column("rules_of_engagement_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tools_executed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_engagements_target", "engagements", ["target"], unique=False)

    op.create_table(
        "runs",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_runs_engagement_id", "runs", ["engagement_id"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("phase", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("finding_type", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("title", sa.String(length=1024), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.String(length=32), nullable=False, server_default="confirmed"),
        sa.Column("evidence_grade", sa.String(length=32), nullable=False, server_default="inferred"),
        sa.Column("claim_severity", sa.String(length=32), nullable=False, server_default="none"),
        sa.Column("source_tool", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("target", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("node_id", sa.String(length=512), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("tags_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("extra_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("raw_data", sa.Text(), nullable=False, server_default=""),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "fingerprint", name="uq_findings_engagement_fingerprint"),
    )
    op.create_index("ix_findings_engagement_id", "findings", ["engagement_id"], unique=False)
    op.create_index("ix_findings_run_id", "findings", ["run_id"], unique=False)
    op.create_index("ix_findings_engagement_type", "findings", ["engagement_id", "finding_type"], unique=False)
    op.create_index("ix_findings_engagement_run", "findings", ["engagement_id", "run_id"], unique=False)
    op.create_index("ix_findings_source_tool", "findings", ["source_tool"], unique=False)
    op.create_index("ix_findings_engagement_severity", "findings", ["engagement_id", "claim_severity"], unique=False)
    op.create_index("ix_findings_engagement_grade", "findings", ["engagement_id", "evidence_grade"], unique=False)

    op.create_table(
        "finding_occurrences",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(length=12), nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("source_tool", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("phase", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("evidence_grade", sa.String(length=32), nullable=False, server_default="inferred"),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_occurrences_finding", "finding_occurrences", ["finding_id"], unique=False)
    op.create_index("ix_finding_occurrences_engagement", "finding_occurrences", ["engagement_id"], unique=False)

    op.create_table(
        "asset_nodes",
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("id", sa.String(length=512), nullable=False),
        sa.Column("asset_type", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=1024), nullable=False),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("source_tool", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("evidence_grade", sa.String(length=32), nullable=False, server_default="inferred"),
        sa.Column("confidence", sa.String(length=32), nullable=False, server_default="confirmed"),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("engagement_id", "id"),
    )
    op.create_index("ix_asset_nodes_engagement_type", "asset_nodes", ["engagement_id", "asset_type"], unique=False)
    op.create_index("ix_asset_nodes_engagement_run", "asset_nodes", ["engagement_id", "run_id"], unique=False)

    op.create_table(
        "asset_edges",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("source_id", sa.String(length=512), nullable=False),
        sa.Column("target_id", sa.String(length=512), nullable=False),
        sa.Column("relationship", sa.String(length=64), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("source_tool", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "engagement_id", "source_id", "target_id", "relationship",
            name="uq_asset_edges_engagement_link",
        ),
    )
    op.create_index("ix_asset_edges_engagement", "asset_edges", ["engagement_id"], unique=False)

    op.create_table(
        "tool_coverage",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("asset", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("success", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("completed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "engagement_id", "tool_name", "asset",
            name="uq_tool_coverage_engagement_tool_asset",
        ),
    )
    op.create_index("ix_tool_coverage_engagement", "tool_coverage", ["engagement_id"], unique=False)

    op.create_table(
        "recovery_observations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("asset", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("error_type", sa.String(length=64), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("shadow_strategy", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("llm_subsequent_tool", sa.String(length=128), nullable=True),
        sa.Column("llm_subsequent_success", sa.Integer(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_recovery_obs_engagement", "recovery_observations", ["engagement_id"], unique=False)
    op.create_index("ix_recovery_obs_tool_error", "recovery_observations", ["tool_name", "error_type"], unique=False)


def downgrade() -> None:
    op.drop_table("recovery_observations")
    op.drop_table("tool_coverage")
    op.drop_index("ix_asset_edges_engagement", table_name="asset_edges")
    op.drop_table("asset_edges")
    op.drop_table("asset_nodes")
    op.drop_table("finding_occurrences")
    op.drop_table("findings")
    op.drop_table("runs")
    op.drop_index("ix_engagements_target", table_name="engagements")
    op.drop_table("engagements")
