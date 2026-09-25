"""Graph nodes/edges carry observation provenance — plans/harness/05-world-
model-and-attack-paths.md Step 1: every edge cites >=1 observation_id, and
node confidence is recomputed fresh from the current evidence set (never
ratcheted) on each ingest.

Revision ID: 0018_graph_obs_provenance
Revises: 0017_suppressed_promotions
Create Date: 2026-09-23

Revision id kept to 25 chars — alembic_version.version_num is VARCHAR(32);
the original "0018_graph_observation_provenance" (33 chars) silently worked
against SQLite (no length enforcement) but broke `upgrade head` on real
Postgres. Filename is left as-is (only the id inside changed).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018_graph_obs_provenance"
down_revision: Union[str, None] = "0017_suppressed_promotions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("asset_nodes") as batch_op:
        batch_op.add_column(
            sa.Column("observation_ids_json", sa.Text(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("source_tools_json", sa.Text(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("conflicts_json", sa.Text(), nullable=False, server_default="{}")
        )
    with op.batch_alter_table("asset_edges") as batch_op:
        batch_op.add_column(
            sa.Column("observation_ids_json", sa.Text(), nullable=False, server_default="[]")
        )


def downgrade() -> None:
    with op.batch_alter_table("asset_edges") as batch_op:
        batch_op.drop_column("observation_ids_json")
    with op.batch_alter_table("asset_nodes") as batch_op:
        batch_op.drop_column("conflicts_json")
        batch_op.drop_column("source_tools_json")
        batch_op.drop_column("observation_ids_json")
