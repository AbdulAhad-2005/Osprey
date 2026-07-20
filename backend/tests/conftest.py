import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Use in-memory SQLite for tests unless TEST_DATABASE_URL is set.
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from pentest_platform.core.config import get_settings  # noqa: E402, F401
