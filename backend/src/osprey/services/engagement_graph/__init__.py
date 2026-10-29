"""Engagement graph service, split into ingest/query mixins + helpers.

EngagementGraph composes _IngestMixin and _QueryMixin; the public surface
(EngagementGraph, get_engagement_graph) is unchanged for callers of
osprey.services.engagement_graph. Module-level helpers live in ._helpers and
are imported directly by the mixins, not re-exported here."""

from __future__ import annotations

import threading

from osprey.services.engagement_graph._ingest import _IngestMixin
from osprey.services.engagement_graph._query import _QueryMixin


class EngagementGraph(_IngestMixin, _QueryMixin):
    def __init__(self) -> None:
        self._lock = threading.Lock()


_graph: EngagementGraph | None = None


def get_engagement_graph() -> EngagementGraph:
    global _graph
    if _graph is None:
        _graph = EngagementGraph()
    return _graph


__all__ = [
    "EngagementGraph",
    "get_engagement_graph",
]
