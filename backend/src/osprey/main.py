from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response, status

from osprey.api.v1.router import api_v1_router
from osprey.contract import APP_VERSION
from osprey.db.migrate import run_migrations
from osprey.services.startup_readiness import (
    mark_failed,
    mark_ready,
    mark_starting,
    snapshot,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    mark_starting()
    try:
        run_migrations()
    except Exception as exc:
        mark_failed(exc)
        logger.exception("Database migration failed — engagement API may not work until Postgres is up")
    else:
        mark_ready()
    # A live job is an asyncio task that cannot survive a restart, so any durable
    # run left 'queued'/'running' from a previous process is orphaned — flip it to
    # a terminal state so poll/list never show a phantom forever-running job.
    try:
        from osprey.services.scan_run_store import get_scan_run_store

        get_scan_run_store().reconcile_orphaned_runs()
    except Exception:
        logger.debug("Orphaned-run reconciliation skipped (non-fatal)", exc_info=True)
    # Restore still-active WAF/rate-limit cooldowns so a restart mid-cooldown
    # doesn't immediately re-hammer a target that just blocked us.
    try:
        from osprey.services.rate_governor import rehydrate_bans

        rehydrate_bans()
    except Exception:
        logger.debug("Ban rehydration skipped (non-fatal)", exc_info=True)
    yield


app = FastAPI(title="Osprey Pentest Platform", version=APP_VERSION, lifespan=lifespan)
app.include_router(api_v1_router, prefix="/api/v1")


@app.get("/health", tags=["health"])
def health(response: Response) -> dict[str, object]:
    payload = snapshot("osprey-backend")
    if not payload["ready"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload
