"""Remove evidence_grade — collapse the redundant grade+confidence axis onto confidence alone.

The 2-D grade x severity system caused false "confirmed/critical" labels (a
scanner pattern-match graded OBSERVED could reach CRITICAL severity with no
proof of exploitation — e.g. a bare sqlmap "is vulnerable" verdict, or any
nuclei template match, both previously OBSERVED by default). Severity is now
assigned honestly by parsers/agents directly (see
skills/vuln/verification-and-severity.md); ``confidence``
(confirmed|likely|hypothesis, already present on Finding) is the sole "how
sure are we" signal.

``asset_nodes`` had the identical duplication (both evidence_grade and
confidence columns, tracking the same idea under two names/vocabularies) —
collapsed to confidence only, with monotonic strengthening in
engagement_graph.py (a node's confidence only ever moves up, never down, as
stronger observations arrive — matching the removed column's behaviour).

Uses batch mode throughout: this project supports SQLite (Path C, no Docker)
as well as Postgres, and SQLite's ALTER TABLE support for column drops/renames
is version-dependent — batch mode recreates the table when needed and is safe
on both backends.

Revision ID: 0012_remove_evidence_grade
Revises: 0011_conversation_messages
Create Date: 2026-09-16
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012_remove_evidence_grade"
down_revision: Union[str, None] = "0011_conversation_messages"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Old grade -> new confidence vocabulary. A renamed column keeps its OLD
# values verbatim — "observed"/"inferred"/"unverified" are not valid
# FindingConfidence members, so existing rows must be translated, not just
# the column relabelled.
_GRADE_TO_CONFIDENCE = {
    "observed": "confirmed",
    "inferred": "likely",
    "unverified": "hypothesis",
}
_CONFIDENCE_TO_GRADE = {v: k for k, v in _GRADE_TO_CONFIDENCE.items()}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # findings: evidence_grade dropped outright — claim_severity is no longer
    # clamped by it; confidence (already present, already in the new
    # vocabulary) is the sole confidence axis.
    finding_columns = {column["name"] for column in inspector.get_columns("findings")}
    if "evidence_grade" in finding_columns:
        finding_indexes = {index["name"] for index in inspector.get_indexes("findings")}
        with op.batch_alter_table("findings") as batch_op:
            if "ix_findings_engagement_grade" in finding_indexes:
                batch_op.drop_index("ix_findings_engagement_grade")
            batch_op.drop_column("evidence_grade")

    # finding_occurrences: evidence_grade renamed to confidence — translate
    # existing values to the new vocabulary BEFORE the rename, while the
    # column is still named evidence_grade.
    occurrence_columns = {
        column["name"] for column in inspector.get_columns("finding_occurrences")
    }
    if "evidence_grade" in occurrence_columns:
        for old, new in _GRADE_TO_CONFIDENCE.items():
            op.execute(
                sa.text(
                    "UPDATE finding_occurrences SET evidence_grade = :new "
                    "WHERE evidence_grade = :old"
                ).bindparams(old=old, new=new)
            )
        with op.batch_alter_table("finding_occurrences") as batch_op:
            batch_op.alter_column(
                "evidence_grade",
                new_column_name="confidence",
                existing_type=sa.String(length=32),
                server_default="likely",
            )

    # asset_nodes: had both evidence_grade and confidence (duplicate axes,
    # same bug as findings) — drop evidence_grade, keep the existing
    # confidence column (already in the new vocabulary, untouched).
    asset_columns = {column["name"] for column in inspector.get_columns("asset_nodes")}
    if "evidence_grade" in asset_columns:
        with op.batch_alter_table("asset_nodes") as batch_op:
            batch_op.drop_column("evidence_grade")
            batch_op.alter_column(
                "confidence",
                existing_type=sa.String(length=32),
                server_default="likely",
            )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(
            sa.Column("evidence_grade", sa.String(length=32), nullable=False, server_default="inferred"),
        )
        batch_op.create_index("ix_findings_engagement_grade", ["engagement_id", "evidence_grade"])

    # Rename back first (column is still called "confidence" at this point),
    # then translate values back to the old vocabulary.
    with op.batch_alter_table("finding_occurrences") as batch_op:
        batch_op.alter_column(
            "confidence",
            new_column_name="evidence_grade",
            existing_type=sa.String(length=32),
            server_default="inferred",
        )
    for new, old in _CONFIDENCE_TO_GRADE.items():
        op.execute(
            sa.text("UPDATE finding_occurrences SET evidence_grade = :old WHERE evidence_grade = :new")
            .bindparams(old=old, new=new)
        )

    with op.batch_alter_table("asset_nodes") as batch_op:
        batch_op.add_column(
            sa.Column("evidence_grade", sa.String(length=32), nullable=False, server_default="inferred"),
        )
        batch_op.alter_column(
            "confidence",
            existing_type=sa.String(length=32),
            server_default="confirmed",
        )
