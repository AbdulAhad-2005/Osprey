"""Run Alembic migrations on backend startup."""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config

from osprey.core.config import get_settings
from osprey.db.base import Base
from osprey.db.session import engine
from osprey.models import (  # noqa: F401
    AssetEdgeRow,
    AssetNodeRow,
    ContextSnapshotRow,
    ConversationMessageRow,
    EngagementRow,
    ExploitCandidateRow,
    ExploitChainRow,
    FindingOccurrenceRow,
    FindingRow,
    RecoveryObservationRow,
    RunRow,
    ScanRunRow,
    SurfaceExpansionRow,
    TargetBanRow,
    ToolCoverageRow,
)

logger = logging.getLogger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[3]


def run_migrations() -> None:
    url = get_settings().database_url
    if url.startswith("sqlite"):
        Base.metadata.create_all(bind=engine)
        logger.info("SQLite schema created via create_all")
        return

    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    command.upgrade(cfg, "head")
    logger.info("Database migrations applied (head)")
