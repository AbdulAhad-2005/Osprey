"""Evidence.raw_excerpt — plans/harness/12-deterministic-evidence-verification.md
Step 1. A durable, synchronously-queryable slice of the tool's actual stdout
at the moment it ran, stored alongside the existing stdout_path/stderr_path
pointer. The pointer alone requires an async docker-exec round-trip into the
Kali container to read back (artifacts.read_artifact_slice) — fragile and
unavailable in native/container-local execution modes, and awkward from the
synchronous file_finding() evidence-grounding gate this plan adds. The
excerpt is captured once, in-process, from the response already in memory
(summary_agent.py, right where the Evidence row is first created) — no new
round-trip, works in every execution mode.

Revision ID: 0021_evidence_raw_excerpt
Revises: 0020_merge_heads
Create Date: 2026-09-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021_evidence_raw_excerpt"
down_revision: Union[str, None] = "0020_merge_heads"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("evidence") as batch_op:
        batch_op.add_column(
            sa.Column("raw_excerpt", sa.Text(), nullable=False, server_default="")
        )


def downgrade() -> None:
    with op.batch_alter_table("evidence") as batch_op:
        batch_op.drop_column("raw_excerpt")
