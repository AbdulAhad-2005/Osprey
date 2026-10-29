"""Engagement graph service, split into ingest/query mixins + helpers.

EngagementGraph composes _IngestMixin and _QueryMixin; the public surface
(EngagementGraph, get_engagement_graph, and the module helpers) is
unchanged for callers of osprey.services.engagement_graph."""

from __future__ import annotations

import threading

from osprey.services.engagement_graph._helpers import (
    logger,
    _IP_RE,
    _node_id,
    _encode_meta,
    _decode_meta,
    _decode_list,
    _decode_conflicts,
    _node_confidence,
)
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
    "logger",
    "_IP_RE",
    "_node_id",
    "_encode_meta",
    "_decode_meta",
    "_decode_list",
    "_decode_conflicts",
    "_node_confidence",
]
