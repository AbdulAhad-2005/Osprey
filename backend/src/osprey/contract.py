"""Public backend identity and compatibility contract.

Keep transport-facing version/capability metadata in one place so the FastAPI
app, health endpoints, CLI, and MCP gateway do not infer compatibility from a
human release string or from endpoint failures.
"""

from __future__ import annotations

APP_VERSION = "0.1.0"
API_CONTRACT_VERSION = 1

# Additive feature identifiers.  Removing or changing the meaning of one is an
# API-contract change; adding one is backward compatible.
CAPABILITIES: tuple[str, ...] = (
    "alembic_sqlite_postgresql",
    "durable_execution_audit",
    "durable_job_history",
    "engagement_pinning",
    "long_poll_jobs",
    "shared_execution_scheduler",
)
