from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import os

from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware

from agent_core.mcp_http import load_mcp_server, mcp_http_enabled
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

# Loaded at import time (not inside lifespan) so app.mount() below can see it
# — a client that only accepts a server URL, not a launch command, then
# points at http://localhost:9000/mcp with zero extra process to run.
_mcp_server = load_mcp_server() if mcp_http_enabled() else None


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
    # The mounted sub-app's own lifespan never runs — the outer app must
    # enter the MCP session manager itself, or the first /mcp request fails
    # with "Task group is not initialized."
    if _mcp_server is not None:
        async with _mcp_server.session_manager.run():
            yield
    else:
        yield


app = FastAPI(title="Osprey Pentest Platform", version=APP_VERSION, lifespan=lifespan)

# The GUI is a browser client. In dev it proxies same-origin (Next rewrites),
# but allow a configured split-origin deployment too. Local-first, so the
# default is just the loopback dev origins; override with OSPREY_CORS_ORIGINS
# (comma-separated, or "*").
_default_cors = "http://localhost:3000,http://localhost:3100,http://127.0.0.1:3000,http://127.0.0.1:3100"
_cors_origins = [o.strip() for o in os.getenv("OSPREY_CORS_ORIGINS", _default_cors).split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if "*" in _cors_origins else _cors_origins,
    allow_credentials="*" not in _cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_v1_router, prefix="/api/v1")


@app.get("/health", tags=["health"])
def health(response: Response) -> dict[str, object]:
    payload = snapshot("osprey-backend")
    if not payload["ready"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


# Mounted LAST: a "/" mount matches every path, so any route added after this
# one would be unreachable. With the default streamable_http_path ("/mcp"),
# the endpoint is just http://localhost:9000/mcp.
if _mcp_server is not None:
    logger.info("Mounting the MCP gateway at /mcp (OSPREY_MCP_HTTP=1)")
    app.mount("/", _mcp_server.streamable_http_app())
