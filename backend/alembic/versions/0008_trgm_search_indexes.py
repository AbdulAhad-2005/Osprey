"""Trigram (pg_trgm) GIN indexes for fast substring recall.

Recall (`memory_search` / `find_correlations` / findings `q=`) filters with
`ILIKE '%needle%'` — a leading-wildcard pattern a btree cannot serve. Every such
query is already narrowed by the `engagement_id` btree first, so it is fast at
today's per-engagement scale; these GIN trigram indexes are forward-looking
insurance so substring search stays fast if a single engagement grows large or a
cross-engagement search is added later. Postgres-only — SQLite (dev/create_all)
keeps plain ILIKE, which is fine at dev scale.

Revision ID: 0008_trgm_search_indexes
Revises: 0007_tool_coverage_event_log
Create Date: 2026-08-22
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0008_trgm_search_indexes"
down_revision: Union[str, None] = "0007_tool_coverage_event_log"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_INDEXES = [
    ("ix_findings_title_trgm", "findings", "title"),
    ("ix_findings_target_trgm", "findings", "target"),
    ("ix_findings_tags_trgm", "findings", "tags_json"),
    ("ix_asset_nodes_label_trgm", "asset_nodes", "label"),
    ("ix_tool_coverage_asset_trgm", "tool_coverage", "asset"),
]


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    for name, table, col in _INDEXES:
        op.execute(
            f"CREATE INDEX IF NOT EXISTS {name} "
            f"ON {table} USING gin ({col} gin_trgm_ops)"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for name, _table, _col in _INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
