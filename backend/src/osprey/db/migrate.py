"""Run Alembic migrations on backend startup."""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, inspect

from osprey.db.session import engine

logger = logging.getLogger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[3]

_APPLICATION_TABLES = {
    "engagements",
    "runs",
    "findings",
    "finding_occurrences",
    "asset_nodes",
    "asset_edges",
    "tool_coverage",
    "recovery_observations",
    "surface_expansion",
    "exploit_candidates",
    "exploit_chains",
    "scan_runs",
    "context_snapshots",
    "target_bans",
    "conversation_messages",
    "audit_entries",
}


def _legacy_revision(connection: Connection) -> str | None:
    """Infer the newest safe revision for an unversioned legacy database.

    Earlier local releases used ``metadata.create_all()`` for SQLite.  That
    created whichever model snapshot happened to ship at the time, but never
    created ``alembic_version`` and never altered an older schema.  Infer the
    last migration whose prerequisites are already present, stamp only that
    revision, then let Alembic perform every remaining transition.

    ``None`` means no Osprey tables exist and the full migration chain should
    run from the baseline.
    """

    inspector = inspect(connection)
    tables = set(inspector.get_table_names())
    application_tables = tables & _APPLICATION_TABLES
    if not application_tables:
        return None
    if "engagements" not in tables:
        raise RuntimeError(
            "Unversioned database contains a partial Osprey schema without "
            "the engagements table; refusing to guess a migration baseline"
        )

    # Infer from the ordered schema additions first.  Stamping the earliest
    # missing step is deliberate: later migrations are idempotent for tables
    # that create_all may already have materialized.
    if "surface_expansion" not in tables:
        return "0001_baseline"
    if "exploit_candidates" not in tables:
        return "0002_surface_expansion"
    if "scan_runs" not in tables:
        if "exploit_chains" in tables:
            return "0005_exploit_chains"
        tool_columns = {
            column["name"] for column in inspector.get_columns("tool_coverage")
        }
        if {"claimed_by", "claimed_at"} <= tool_columns:
            return "0004_tool_coverage_claims"
        return "0003_exploit_candidates"

    tool_columns = {
        column["name"] for column in inspector.get_columns("tool_coverage")
    }
    unique_constraints = {
        constraint.get("name")
        for constraint in inspector.get_unique_constraints("tool_coverage")
    }
    if (
        "claimed_by" in tool_columns
        or "claimed_at" in tool_columns
        or "uq_tool_coverage_engagement_tool_asset" in unique_constraints
    ):
        return "0006_scan_runs"

    # 0008 is Postgres-only, so a SQLite schema at 0007 is structurally
    # indistinguishable from 0008.  Stamp 0008 to continue at the first real
    # SQLite addition.
    if "context_snapshots" not in tables:
        return "0008_trgm_search_indexes"
    if "target_bans" not in tables:
        return "0009_context_snapshots"
    if "conversation_messages" not in tables:
        return "0010_target_bans"

    findings_columns = {
        column["name"] for column in inspector.get_columns("findings")
    }
    occurrence_columns = {
        column["name"] for column in inspector.get_columns("finding_occurrences")
    }
    asset_columns = {
        column["name"] for column in inspector.get_columns("asset_nodes")
    }
    if (
        "evidence_grade" in findings_columns
        or "evidence_grade" in occurrence_columns
        or "evidence_grade" in asset_columns
    ):
        return "0011_conversation_messages"
    if "exploit_chains" in tables:
        return "0012_remove_evidence_grade"
    return "0013_drop_exploit_chains"


def _alembic_config(connection: Connection) -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option(
        "sqlalchemy.url",
        connection.engine.url.render_as_string(hide_password=False),
    )
    # Reuse the already-configured application connection.  This avoids a
    # second engine with subtly different SQLite connection semantics and
    # makes migration behavior deterministic in tests.
    cfg.attributes["connection"] = connection
    return cfg


def run_migrations() -> None:
    # Alembic's SQLite DDL is non-transactional, but the version-table writes
    # are not.  Own and commit the outer transaction so schema changes and the
    # recorded revision cannot diverge.
    with engine.begin() as connection:
        cfg = _alembic_config(connection)
        tables = set(inspect(connection).get_table_names())
        if "alembic_version" not in tables:
            revision = _legacy_revision(connection)
            if revision is not None:
                command.stamp(cfg, revision)
                logger.info("Stamped legacy unversioned database at %s", revision)
        command.upgrade(cfg, "head")
    logger.info("Database migrations applied (head)")
