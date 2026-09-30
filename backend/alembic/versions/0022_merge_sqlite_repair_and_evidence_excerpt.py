"""Merge the SQLite-default repair and evidence-excerpt branches.

Revision ID: 0022_merge_0021_heads
Revises: 0021_fix_sqlite_now_default, 0021_evidence_raw_excerpt
Create Date: 2026-09-29
"""

from __future__ import annotations

from typing import Sequence, Union


revision: str = "0022_merge_0021_heads"
down_revision: Union[str, tuple[str, str], None] = (
    "0021_fix_sqlite_now_default",
    "0021_evidence_raw_excerpt",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Both parent migrations contain the required schema operations."""


def downgrade() -> None:
    """Downgrading the merge separates the graph back into its two parents."""

