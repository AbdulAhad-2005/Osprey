"""Finding evidence provenance — plans/harness/03-earned-finding-pipeline.md Step 1.

A Finding becomes a claim + its evidence: ``observation_ids`` (what it's
about), ``source_tools`` (who corroborated it), ``evidence_records`` (typed
corroboration/reproduction/verification/attestation items — the input to
``confidence_for``), ``evidence_summary`` (human-readable digest).

Revision ID: 0015_finding_evidence_provenance
Revises: 0014_evidence_and_observations
Create Date: 2026-09-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015_finding_evidence_provenance"
down_revision: Union[str, None] = "0014_evidence_and_observations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(
            sa.Column("observation_ids_json", sa.Text(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("source_tools_json", sa.Text(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("evidence_records_json", sa.Text(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("evidence_summary", sa.Text(), nullable=False, server_default="")
        )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("evidence_summary")
        batch_op.drop_column("evidence_records_json")
        batch_op.drop_column("source_tools_json")
        batch_op.drop_column("observation_ids_json")
