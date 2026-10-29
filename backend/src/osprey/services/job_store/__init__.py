"""Background-job store, split into query/exec mixins + helpers.

JobStore composes the query/exec mixins; the public surface (JobStore,
get_job_store, suggest_background, _JobRecord) is unchanged for callers of
osprey.services.job_store. Other module helpers live in ._helpers and are
imported directly by the mixins, not re-exported here."""

from __future__ import annotations

import threading

from osprey.services.job_store._helpers import _JobRecord
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
    "_JobRecord",
]
