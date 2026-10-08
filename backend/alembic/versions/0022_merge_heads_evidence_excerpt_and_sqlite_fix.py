"""merge evidence_raw_excerpt and fix_sqlite_now_default heads

Both 0021 revisions were authored independently off the same parent
(``0020_merge_heads``) and neither was made a child of the other, so alembic
saw two heads and refused to run at all:

    CommandError: Multiple head revisions are present for given argument 'head'

That blocks every migration on the stack, not just these two. The two are
independent and safe to run in either order:

* ``0021_evidence_raw_excerpt`` adds ``evidence.raw_excerpt`` — applies on
  both dialects.
* ``0021_fix_sqlite_now_default`` repairs a stale ``now()`` column default
  baked into 7 tables on databases created before ``sa.func.now()`` compiled
  correctly for SQLite. Its ``upgrade()`` returns immediately on any
  non-SQLite dialect, so on Postgres it is a no-op.

Revision ID: 0022_merge_heads
Revises: 0021_evidence_raw_excerpt, 0021_fix_sqlite_now_default
Create Date: 2026-09-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0022_merge_heads'
down_revision: Union[str, None] = ('0021_evidence_raw_excerpt', '0021_fix_sqlite_now_default')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
