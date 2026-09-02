from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from osprey.core.config import get_settings

settings = get_settings()

# SQLite is the zero-dependency fallback for native/local runs (set
# DATABASE_URL=sqlite:///./pentest.db). It needs check_same_thread=False because
# FastAPI serves requests from a threadpool; run_migrations() bootstraps the
# schema via create_all for sqlite (see db/migrate.py).
_engine_kwargs: dict = {"pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.database_url, **_engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
