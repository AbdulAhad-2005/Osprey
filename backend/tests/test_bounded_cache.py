"""B5.1 — per-engagement process caches cap their key count (no unbounded
growth in a long-lived backend process)."""

from __future__ import annotations

from osprey.services import context_delta, event_bus, stdout_index
from osprey.services.bounded_cache import cap_lru, cap_lru_skip


def test_cap_lru_evicts_oldest_first():
    store = {}
    for i in range(10):
        store[f"e{i}"] = i
        cap_lru(store, max_keys=5)
    assert len(store) == 5
    assert list(store) == ["e5", "e6", "e7", "e8", "e9"]


def test_cap_lru_skip_never_evicts_protected_key():
    store = {f"e{i}": i for i in range(6)}
    cap_lru_skip(store, skip={"e0"}, max_keys=3)
    assert "e0" in store
    assert len(store) == 3


def test_context_delta_store_is_bounded(monkeypatch):
    monkeypatch.setattr(context_delta, "_STORE", {})
    monkeypatch.setattr("osprey.services.bounded_cache.MAX_CACHED_ENGAGEMENTS", 64)
    for i in range(80):
        context_delta.snapshot_counts(f"eng-{i}.test", nodes=i)
    assert len(context_delta._STORE) <= 64


def test_stdout_index_is_bounded(monkeypatch):
    monkeypatch.setattr(stdout_index, "_INDEX", {})
    for i in range(80):
        stdout_index.record_stdout_entry(engagement_id=f"eng-{i}.test", tool_name="httpx_probe")
    assert len(stdout_index._INDEX) <= 64


def test_event_bus_history_is_bounded(monkeypatch):
    monkeypatch.setattr(event_bus, "_history", {})
    monkeypatch.setattr(event_bus, "_subscribers", {})
    for i in range(80):
        event_bus.publish(f"eng-{i}.test", "tool_start", {"n": i})
    assert len(event_bus._history) <= 64
