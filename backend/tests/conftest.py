"""Pytest configuration and environment fixtures for osprey tests."""

import os
from pathlib import Path

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
