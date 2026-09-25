"""FP-cache store — plans/harness/04-learning-fp-cache.md Step 1."""

from __future__ import annotations

import pytest

from osprey.services import fp_cache


@pytest.fixture(autouse=True)
def _isolated_cache_file(tmp_path, monkeypatch):
    """Never touch the real operator-local fp_cache/patterns.jsonl from tests."""
    monkeypatch.setattr(fp_cache, "_FP_CACHE_DIR", tmp_path / "fp_cache")
    monkeypatch.setattr(fp_cache, "_PATTERNS_PATH", tmp_path / "fp_cache" / "patterns.jsonl")
    fp_cache.reload()
    yield
    fp_cache.reload()


def test_add_and_list_pattern():
    p = fp_cache.add_pattern(title_contains="501 Not Implemented", reason="scanner noise")
    patterns = fp_cache.list_patterns()
    assert len(patterns) == 1
    assert patterns[0].id == p.id
    assert patterns[0].target_glob == "*"


def test_add_pattern_requires_a_matchable_field():
    with pytest.raises(ValueError):
        fp_cache.add_pattern(title_contains="", observation_signature="")


def test_matches_by_title_substring_cross_engagement_by_default():
    fp_cache.add_pattern(title_contains="501 Not Implemented", reason="known noise")
    hit = fp_cache.matches(target="any-target.test", title="GET /legacy 501 Not Implemented")
    assert hit is not None
    assert hit.reason == "known noise"

    miss = fp_cache.matches(target="any-target.test", title="Something else entirely")
    assert miss is None


def test_matches_scoped_by_target_glob():
    fp_cache.add_pattern(target_glob="*.internal.test", title_contains="self-signed cert")
    hit = fp_cache.matches(target="api.internal.test", title="self-signed cert detected")
    assert hit is not None
    miss = fp_cache.matches(target="external.example.com", title="self-signed cert detected")
    assert miss is None


def test_matches_scoped_by_finding_type():
    fp_cache.add_pattern(finding_type="technology", title_contains="nginx")
    hit = fp_cache.matches(target="x.test", finding_type="technology", title="nginx banner")
    assert hit is not None
    miss = fp_cache.matches(target="x.test", finding_type="vulnerability", title="nginx banner")
    assert miss is None


def test_matches_by_observation_signature_exact():
    fp_cache.add_pattern(observation_signature="sig-abc123")
    hit = fp_cache.matches(target="x.test", title="anything", observation_signatures=["sig-abc123", "sig-other"])
    assert hit is not None
    miss = fp_cache.matches(target="x.test", title="anything", observation_signatures=["sig-other"])
    assert miss is None


def test_remove_pattern():
    p = fp_cache.add_pattern(title_contains="noise")
    assert fp_cache.remove_pattern(p.id) is True
    assert fp_cache.list_patterns() == []
    assert fp_cache.remove_pattern(p.id) is False


def test_patterns_persist_across_reload():
    fp_cache.add_pattern(title_contains="persisted noise")
    fp_cache.reload()
    patterns = fp_cache.list_patterns()
    assert len(patterns) == 1
    assert patterns[0].title_contains == "persisted noise"
