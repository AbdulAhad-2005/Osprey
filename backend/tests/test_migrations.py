"""Migration-path tests for fresh and pre-Alembic SQLite databases."""

from __future__ import annotations

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from osprey.db import migrate
from osprey.db.base import Base
from sqlalchemy import create_engine, inspect, text


def _sqlite_engine(tmp_path, name: str):
    return create_engine(f"sqlite:///{(tmp_path / name).as_posix()}")


def _expected_head() -> str:
    """The single current head, derived from the migration scripts — never
    hardcoded, so adding a migration (or a merge revision) doesn't break this
    test. ``get_current_head()`` also raises if the graph has multiple heads,
    so this doubles as a single-head guard."""
    cfg = Config(str(migrate._BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(migrate._BACKEND_ROOT / "alembic"))
    return ScriptDirectory.from_config(cfg).get_current_head()


def _assert_at_head(engine) -> None:
    with engine.begin() as connection:
        version = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
        inspector = inspect(connection)
        assert version == _expected_head()
        assert "audit_entries" in inspector.get_table_names()
        scan_columns = {
            column["name"] for column in inspector.get_columns("scan_runs")
        }
        assert {"request_json", "command_preview", "heartbeat_at"} <= scan_columns
        assert "exploit_chains" not in inspector.get_table_names()
        assert "evidence_grade" not in {
            column["name"] for column in inspector.get_columns("findings")
        }
        assert "confidence" in {
            column["name"]
            for column in inspector.get_columns("finding_occurrences")
        }


def test_fresh_sqlite_runs_complete_alembic_chain(tmp_path, monkeypatch) -> None:
    engine = _sqlite_engine(tmp_path, "fresh.db")
    monkeypatch.setattr(migrate, "engine", engine)

    migrate.run_migrations()

    _assert_at_head(engine)


def test_current_unversioned_create_all_database_is_stamped(tmp_path, monkeypatch) -> None:
    engine = _sqlite_engine(tmp_path, "current-unversioned.db")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(migrate, "engine", engine)

    migrate.run_migrations()

    _assert_at_head(engine)


def test_legacy_pre_confidence_schema_is_upgraded_without_data_loss(
    tmp_path,
    monkeypatch,
) -> None:
    engine = _sqlite_engine(tmp_path, "legacy-0011.db")
    with engine.begin() as connection:
        cfg = migrate._alembic_config(connection)
        command.upgrade(cfg, "0011_conversation_messages")
        connection.execute(
            text(
                "INSERT INTO engagements (id, target, name) "
                "VALUES ('eng-legacy', 'example.test', 'legacy')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO findings "
                "(id, engagement_id, finding_type, fingerprint, title, "
                "confidence, evidence_grade) VALUES "
                "('finding-1', 'eng-legacy', 'host', 'fp-1', 'legacy host', "
                "'confirmed', 'observed')"
            )
        )
        connection.execute(text("DROP TABLE alembic_version"))

    monkeypatch.setattr(migrate, "engine", engine)
    migrate.run_migrations()

    _assert_at_head(engine)
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT title FROM findings WHERE id = 'finding-1'")
        ).scalar_one() == "legacy host"
