"""Repair a stale SQLite DEFAULT (now()) baked into 7 tables on databases
created before ``sa.func.now()`` correctly compiled to ``CURRENT_TIMESTAMP``
for SQLite. ``now()`` is not a SQLite function — every INSERT relying on the
column default (i.e., every caller that doesn't supply the timestamp
explicitly) silently failed with ``sqlite3.OperationalError: unknown
function: now()``, confirmed live: every Evidence/Observation/Hypothesis/
Question/AttackPath/SuppressedPromotion row insert on an affected database
has been failing since these tables were created. Postgres was never
affected (it has a real ``now()`` function); this migration is a no-op there.

SQLite has no ``ALTER COLUMN ... SET DEFAULT`` — the standard, safe repair is
the well-known "12-step" pattern: recreate the table with the corrected
definition, copy the data across by column name, drop the old table, restore
the indexes. Idempotent: a table already using the correct default (a fresh
database, or one already repaired) is left untouched.

Revision ID: 0021_fix_sqlite_now_default
Revises: 0020_merge_heads
Create Date: 2026-09-25
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021_fix_sqlite_now_default"
down_revision: Union[str, None] = "0020_merge_heads"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (table_name, column_defs, index_defs) — column/index definitions copied
# verbatim from the migrations that originally created each table (0014, 0017,
# 0019), which already use sa.func.now() correctly. This migration exists to
# retroactively apply that same correct definition to a table that was created
# with the broken literal baked in.
_TABLES: list[tuple[str, list[sa.Column], list[tuple[str, list[str], bool]]]] = [
    (
        "evidence",
        [
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
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        ],
        [
            ("ix_evidence_engagement", ["engagement_id"], False),
            ("ix_evidence_engagement_run", ["engagement_id", "run_id"], False),
            ("ix_evidence_tool", ["tool_name"], False),
        ],
    ),
    (
        "observations",
        [
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
            sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        ],
        [
            ("ix_observations_engagement_type", ["engagement_id", "type"], False),
            ("ix_observations_engagement_target", ["engagement_id", "target"], False),
            ("ix_observations_evidence", ["evidence_id"], False),
            ("ix_observations_engagement", ["engagement_id"], False),
        ],
    ),
    (
        "observation_occurrences",
        [
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("observation_id", sa.String(length=12), nullable=False),
            sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("run_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("evidence_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("source_tool", sa.String(length=128), nullable=False, server_default=""),
            sa.Column("extracted_by", sa.String(length=16), nullable=False, server_default="parser"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        ],
        [
            ("ix_observation_occurrences_observation", ["observation_id"], False),
            ("ix_observation_occurrences_engagement", ["engagement_id"], False),
        ],
    ),
    (
        "suppressed_promotions",
        [
            sa.Column("id", sa.String(length=12), nullable=False),
            sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("observation_id", sa.String(length=64), nullable=False, server_default=""),
            sa.Column("pattern_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("title", sa.String(length=1024), nullable=False, server_default=""),
            sa.Column("reason", sa.Text(), nullable=False, server_default=""),
            sa.Column("suppressed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        ],
        [
            ("ix_suppressed_promotions_engagement", ["engagement_id"], False),
        ],
    ),
    (
        "attack_paths",
        [
            sa.Column("id", sa.String(length=12), nullable=False),
            sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("title", sa.String(length=500), nullable=False, server_default=""),
            sa.Column("steps_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="hypothesized"),
            sa.Column("finding_id", sa.String(length=64), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        ],
        [
            ("ix_attack_paths_engagement", ["engagement_id"], False),
            ("ix_attack_paths_engagement_status", ["engagement_id", "status"], False),
        ],
    ),
    (
        "questions",
        [
            sa.Column("id", sa.String(length=12), nullable=False),
            sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("text", sa.Text(), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
            sa.Column("raised_by", sa.String(length=32), nullable=False, server_default="llm"),
            sa.Column("related_asset_id", sa.String(length=512), nullable=False, server_default=""),
            sa.Column("answer", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        ],
        [
            ("ix_questions_engagement", ["engagement_id"], False),
            ("ix_questions_engagement_status", ["engagement_id", "status"], False),
        ],
    ),
    (
        "hypotheses",
        [
            sa.Column("id", sa.String(length=12), nullable=False),
            sa.Column("engagement_id", sa.String(length=12), nullable=False, server_default=""),
            sa.Column("statement", sa.Text(), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
            sa.Column("supporting_observation_ids_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("contradicting_observation_ids_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        ],
        [
            ("ix_hypotheses_engagement", ["engagement_id"], False),
            ("ix_hypotheses_engagement_status", ["engagement_id", "status"], False),
        ],
    ),
]


def _table_has_now_bug(conn, table_name: str) -> bool:
    row = conn.execute(
        sa.text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:n"),
        {"n": table_name},
    ).fetchone()
    if row is None or row[0] is None:
        return False  # table doesn't exist yet — a later migration creates it correctly
    return "DEFAULT (now())" in row[0] or "default (now())" in row[0].lower()


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        return  # Postgres has a real now() — never affected

    conn = bind
    conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
    try:
        for table_name, columns, indexes in _TABLES:
            if not _table_has_now_bug(conn, table_name):
                continue  # already correct (fresh db, or already repaired) — idempotent

            legacy_name = f"{table_name}__legacy_now_bug"
            col_names = [c.name for c in columns]

            # PRIMARY KEY / FOREIGN KEY constraints must be re-declared explicitly —
            # sa.Column(..., nullable=False) alone (as used above, mirroring the
            # original CREATE TABLE calls) does not imply a primary key.
            pk_cols = ["id"]
            fk_constraints = []
            if table_name == "observation_occurrences":
                fk_constraints.append(
                    sa.ForeignKeyConstraint(["observation_id"], ["observations.id"], ondelete="CASCADE")
                )
            unique_constraints = []
            if table_name == "observations":
                unique_constraints.append(
                    sa.UniqueConstraint("engagement_id", "signature", name="uq_observations_engagement_signature")
                )

            op.rename_table(table_name, legacy_name)
            op.create_table(
                table_name,
                *[c.copy() for c in columns],
                *fk_constraints,
                sa.PrimaryKeyConstraint(*pk_cols),
                *unique_constraints,
            )
            cols_sql = ", ".join(col_names)
            conn.exec_driver_sql(
                f"INSERT INTO {table_name} ({cols_sql}) SELECT {cols_sql} FROM {legacy_name}"
            )
            op.drop_table(legacy_name)
            for idx_name, idx_cols, unique in indexes:
                op.create_index(idx_name, table_name, idx_cols, unique=unique)
    finally:
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")


def downgrade() -> None:
    # This is a data-preserving repair of a bug, not a schema feature — there is
    # nothing meaningful to revert to (the "old" state is the broken one).
    pass
