"""LRU command-result cache (stripped of logging noise)."""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Optional


class CommandCache:
    """Cache successful tool runs keyed by command string + parameters."""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600) -> None:
        self._store: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def _key(self, command: str, params: dict[str, Any]) -> str:
        payload = f"{command}:{json.dumps(params, sort_keys=True, default=str)}"
        return hashlib.md5(payload.encode()).hexdigest()

    def _expired(self, timestamp: float) -> bool:
        return time.time() - timestamp > self.ttl_seconds

    def get(self, command: str, params: dict[str, Any] | None = None) -> Optional[dict[str, Any]]:
        params = params or {}
        key = self._key(command, params)
        entry = self._store.get(key)
        if entry is None:
            self.stats["misses"] += 1
            return None
        timestamp, data = entry
        if self._expired(timestamp):
            del self._store[key]
            self.stats["misses"] += 1
            return None
        self._store.move_to_end(key)
        self.stats["hits"] += 1
        return data

    def set(self, command: str, params: dict[str, Any] | None, result: dict[str, Any]) -> None:
        params = params or {}
        key = self._key(command, params)
        while len(self._store) >= self.max_size:
            self._store.popitem(last=False)
            self.stats["evictions"] += 1
        self._store[key] = (time.time(), result)

    def stats_dict(self) -> dict[str, Any]:
        total = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total * 100) if total else 0.0
        return {
            "size": len(self._store),
            "max_size": self.max_size,
            "hit_rate_pct": round(hit_rate, 1),
            **self.stats,
        }
