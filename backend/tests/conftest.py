"""Pytest configuration and environment fixtures for osprey tests."""

import os
import sys
from pathlib import Path

# Some tests exercise code that imports the sibling ``cli`` package at runtime
# (e.g. agent_runner -> cli.agent.loop). Put the repo root on sys.path so
# ``import cli`` resolves; tests whose cli deps (rich, etc.) are absent in a
# backend-only venv skip via importorskip rather than aborting collection.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Tests must NEVER run against the application's own configured DATABASE_URL —
# only an explicit, dedicated OSPREY_TEST_DATABASE_URL (for CI pointing at a
# disposable Postgres) opts out of the default isolated-per-process SQLite file.
test_db_url = os.environ.get("OSPREY_TEST_DATABASE_URL", "")
if test_db_url:
    os.environ["DATABASE_URL"] = test_db_url
else:
    test_root = Path(__file__).resolve().parents[1] / ".pytest-tmp"
    test_root.mkdir(parents=True, exist_ok=True)
    test_db = test_root / f"osprey-tests-{os.getpid()}.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{test_db.as_posix()}"


# A conftest-local pytest_sessionstart hook is registered too late on some
# runners (session start precedes collection).  Build the isolated schema as
# soon as this file is imported, before any application module opens a store.
from osprey.db.migrate import run_migrations  # noqa: E402

run_migrations()
