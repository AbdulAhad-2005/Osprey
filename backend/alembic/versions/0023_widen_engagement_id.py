"""Widen engagement_id (and engagements.id) from String(12) to String(32).

Engagement ids are now human-readable slugs derived from the target
("geo1", "geo2", "samaa1", ...) instead of a 12-char uuid blob — see
engagement_store.py's _slugify_target/_next_engagement_id. A slug plus a
growing counter can exceed 12 characters, so every column that stores or
references an engagement id needs headroom. 32 is generous without being
unbounded; slugs are already capped at 16 chars.

Uses batch mode throughout: SQLite's ALTER TABLE column-type support is
version-dependent, and batch mode (recreate + copy) works identically on
both backends. Postgres also accepts these as more-permissive VARCHAR
widenings — no data rewrite, no risk of truncation.

Revision ID: 0023_widen_engagement_id
Revises: 0022_merge_0021_heads
Create Date: 2026-09-29
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0023_widen_engagement_id"
down_revision: Union[str, None] = "0022_merge_0021_heads"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_OLD = 12
_NEW = 32

# (table, column, is_primary_key)
_COLUMNS: list[tuple[str, str, bool]] = [
    ("engagements", "id", True),
    ("runs", "engagement_id", False),
    ("attack_paths", "engagement_id", False),
    ("audit_entries", "engagement_id", False),
    ("context_snapshots", "engagement_id", True),
    ("conversation_messages", "engagement_id", False),
    ("evidence", "engagement_id", False),
    ("exploit_candidates", "engagement_id", False),
    ("findings", "engagement_id", False),
    ("finding_occurrences", "engagement_id", False),
    ("asset_nodes", "engagement_id", True),
    ("asset_edges", "engagement_id", False),
    ("observations", "engagement_id", False),
    ("observation_occurrences", "engagement_id", False),
    ("questions", "engagement_id", False),
    ("hypotheses", "engagement_id", False),
    ("recovery_observations", "engagement_id", False),
    ("scan_runs", "engagement_id", False),
    ("suppressed_promotions", "engagement_id", False),
    ("surface_expansion", "engagement_id", False),
    ("target_bans", "engagement_id", True),
    ("tool_coverage", "engagement_id", False),
]


def _alter(table: str, column: str, *, from_length: int, to_length: int, primary_key: bool) -> None:
    with op.batch_alter_table(table) as batch_op:
        kwargs = {"existing_type": sa.String(length=from_length)}
        if primary_key:
            kwargs["existing_nullable"] = False
        batch_op.alter_column(column, type_=sa.String(length=to_length), **kwargs)


def upgrade() -> None:
    for table, column, pk in _COLUMNS:
        _alter(table, column, from_length=_OLD, to_length=_NEW, primary_key=pk)


def downgrade() -> None:
    for table, column, pk in reversed(_COLUMNS):
        _alter(table, column, from_length=_NEW, to_length=_OLD, primary_key=pk)
