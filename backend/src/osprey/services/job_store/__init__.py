"""Background-job store, split into query/exec mixins + helpers.

JobStore composes the mixins; the public surface (JobStore, get_job_store,
suggest_background, and the module helpers/records) is unchanged for
callers of osprey.services.job_store."""

from __future__ import annotations
import threading

from osprey.services.job_store._helpers import (
    logger,
    _MAX_JOBS_KEPT,
    _JOB_MAX_TIMEOUT,
    _PRUNE_GRACE_SECONDS,
    _JobRecord,
    _serialize_result,
    _SLUG_RE,
    _slugify_tool,
    _next_job_id,
    _default_label,
    _preview,
    _epoch,
    _durable_summary_from_row,
    _durable_summary,
)
from osprey.services.job_store._query import _QueryMixin
from osprey.services.job_store._exec import _ExecMixin


class JobStore(_QueryMixin, _ExecMixin):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, _JobRecord] = {}



_store: JobStore | None = None


def get_job_store() -> JobStore:
    global _store
    if _store is None:
        _store = JobStore()
    return _store


def suggest_background(tool_name: str, timeout: int) -> bool:
    """Heuristic: long tools / high timeouts should be branched (config-driven)."""
    from osprey.services.parallelism_config import suggest_background as _sug

    return _sug(tool_name, timeout)

__all__ = [
    "JobStore",
    "get_job_store",
    "suggest_background",
    "logger",
    "_MAX_JOBS_KEPT",
    "_JOB_MAX_TIMEOUT",
    "_PRUNE_GRACE_SECONDS",
    "_JobRecord",
    "_serialize_result",
    "_SLUG_RE",
    "_slugify_tool",
    "_next_job_id",
    "_default_label",
    "_preview",
    "_epoch",
    "_durable_summary_from_row",
    "_durable_summary",
]
