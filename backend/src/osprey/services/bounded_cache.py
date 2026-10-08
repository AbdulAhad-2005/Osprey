"""Bound per-engagement process caches so the key count can't grow without
limit in a long-lived backend process (B5.1). Each per-engagement value is
already individually bounded; this caps how many engagements are kept."""

from __future__ import annotations

from typing import TypeVar

# Mirrors commander_context._CTX_CACHE_MAX — the one already-bounded cache.
MAX_CACHED_ENGAGEMENTS = 64

_K = TypeVar("_K")
_V = TypeVar("_V")


def cap_lru(store: dict[_K, _V], max_keys: int = MAX_CACHED_ENGAGEMENTS) -> None:
    """Evict oldest-inserted keys until ``len(store) <= max_keys``. Call it right
    after (re)inserting the current key so that key sits newest — dicts preserve
    insertion order, so popping ``next(iter(store))`` drops the least-recently
    written engagement."""
    while len(store) > max_keys:
        store.pop(next(iter(store)))


def cap_lru_skip(
    store: dict[_K, _V], *, skip: set[_K], max_keys: int = MAX_CACHED_ENGAGEMENTS
) -> None:
    """Like ``cap_lru`` but never evicts a key in ``skip`` (e.g. an engagement
    with a live subscriber). Scans oldest-first, evicting the first non-skipped
    key each pass; stops if only skipped keys remain."""
    while len(store) > max_keys:
        victim = next((k for k in store if k not in skip), None)
        if victim is None:
            return
        store.pop(victim)
