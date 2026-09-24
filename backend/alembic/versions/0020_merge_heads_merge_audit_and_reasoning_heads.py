"""merge audit and reasoning heads

Revision ID: 0020_merge_heads
Revises: 0014_durable_audit_entries, 0019_attack_paths_and_reasoning
Create Date: 2026-09-24 23:45:02.820339

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0020_merge_heads'
down_revision: Union[str, None] = ('0014_durable_audit_entries', '0019_attack_paths_and_reasoning')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
