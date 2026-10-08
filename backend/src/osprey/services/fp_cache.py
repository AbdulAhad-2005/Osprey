"""FP-cache — plans/harness/04-learning-fp-cache.md Step 1.

An append-only, operator-local, git-ignored JSONL file — same storage shape
as ``services/learned_skills.py``'s ``skills/learned/`` (a human judgment,
persisted locally, never synced/committed since it can embed engagement
detail in ``title_contains``/``reason``). Loaded once and cached in memory;
``reload()`` invalidates the cache after a write from another process.
"""

from __future__ import annotations

import fnmatch
import json
import threading
from pathlib import Path

from osprey.schemas.fp_cache import FpPattern

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_FP_CACHE_DIR = _PROJECT_ROOT / "fp_cache"
_PATTERNS_PATH = _FP_CACHE_DIR / "patterns.jsonl"

_lock = threading.Lock()
_cache: list[FpPattern] | None = None


def _load_from_disk() -> list[FpPattern]:
    if not _PATTERNS_PATH.is_file():
        return []
    patterns: list[FpPattern] = []
    for line in _PATTERNS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            patterns.append(FpPattern.model_validate_json(line))
        except ValueError:
            continue
    return patterns


def _write_to_disk(patterns: list[FpPattern]) -> None:
    _FP_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _PATTERNS_PATH.write_text(
        "\n".join(p.model_dump_json() for p in patterns) + ("\n" if patterns else ""),
        encoding="utf-8",
    )


def reload() -> None:
    global _cache
    with _lock:
        _cache = None


def list_patterns() -> list[FpPattern]:
    global _cache
    with _lock:
        if _cache is None:
            _cache = _load_from_disk()
        return list(_cache)


def compute_finding_fingerprint(finding_type: str, title: str) -> str:
    """A target-independent structural claim key: finding_type|normalized-title
    (lowercased, whitespace-collapsed), matched EXACTLY — never as a substring.
    Target scoping is done separately by target_glob, so this is what lets an
    operator suppress the same claim across targets with an explicit wildcard
    scope. Exact match (not substring) is what kills the over-suppression a
    short title substring used to cause."""
    ft = (finding_type or "").strip().lower()
    norm = " ".join((title or "").split()).strip().lower()
    if not ft or not norm:
        return ""
    return f"{ft}|{norm}"


def add_pattern(
    *,
    target_glob: str = "*",
    finding_type: str = "",
    observation_signature: str = "",
    finding_fingerprint: str = "",
    reason: str = "",
    marked_by: str = "operator",
) -> FpPattern:
    if not (observation_signature or "").strip() and not (finding_fingerprint or "").strip():
        raise ValueError("A pattern needs observation_signature or finding_fingerprint to match on.")
    pattern = FpPattern(
        target_glob=(target_glob or "*").strip() or "*",
        finding_type=(finding_type or "").strip().lower(),
        observation_signature=(observation_signature or "").strip(),
        finding_fingerprint=(finding_fingerprint or "").strip(),
        reason=(reason or "").strip(),
        marked_by=(marked_by or "operator").strip(),
    )
    global _cache
    with _lock:
        patterns = _cache if _cache is not None else _load_from_disk()
        patterns.append(pattern)
        _write_to_disk(patterns)
        _cache = patterns
    return pattern


def remove_pattern(pattern_id: str) -> bool:
    global _cache
    with _lock:
        patterns = _cache if _cache is not None else _load_from_disk()
        remaining = [p for p in patterns if p.id != pattern_id]
        if len(remaining) == len(patterns):
            return False
        _write_to_disk(remaining)
        _cache = remaining
        return True


def matches(
    *,
    target: str,
    finding_type: str = "",
    observation_signatures: list[str] | None = None,
    finding_fingerprint: str = "",
) -> FpPattern | None:
    """First pattern (if any) matching this candidate. A pattern matches when
    its target_glob matches the target AND (its finding_type is empty or equals
    the candidate's) AND (its observation_signature is among the candidate's, OR
    its finding_fingerprint equals the candidate's). No title-substring path."""
    tgt = (target or "").strip().lower()
    ftype = (finding_type or "").strip().lower()
    fp = (finding_fingerprint or "").strip()
    sigs = set(observation_signatures or [])
    for p in list_patterns():
        if not fnmatch.fnmatch(tgt, p.target_glob.strip().lower() or "*"):
            continue
        if p.finding_type and p.finding_type != ftype:
            continue
        if p.observation_signature and p.observation_signature in sigs:
            return p
        if p.finding_fingerprint and fp and p.finding_fingerprint == fp:
            return p
    return None
