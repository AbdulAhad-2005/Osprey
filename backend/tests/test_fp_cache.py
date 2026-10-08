"""FP-cache store — structured matching only (B2): observation_signature or
finding_fingerprint, never a title substring."""

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
    p = fp_cache.add_pattern(observation_signature="sig-501", reason="scanner noise")
    patterns = fp_cache.list_patterns()
    assert len(patterns) == 1
    assert patterns[0].id == p.id
    assert patterns[0].target_glob == "*"


def test_add_pattern_requires_a_matchable_field():
    with pytest.raises(ValueError):
        fp_cache.add_pattern(observation_signature="", finding_fingerprint="")


def test_matches_by_finding_fingerprint_exact_not_substring():
    fp = fp_cache.compute_finding_fingerprint("vulnerability", "501 Not Implemented")
    fp_cache.add_pattern(finding_fingerprint=fp, finding_type="vulnerability", reason="known noise")
    # Exact normalized title+type matches (case/whitespace-insensitive).
    hit = fp_cache.matches(
        target="any-target.test", finding_type="vulnerability",
        finding_fingerprint=fp_cache.compute_finding_fingerprint("vulnerability", "501 NOT  Implemented"),
    )
    assert hit is not None and hit.reason == "known noise"

    # A longer unrelated title that merely CONTAINS the words no longer matches
    # (the B2 fix — substring over-suppression is gone).
    miss = fp_cache.matches(
        target="any-target.test", finding_type="vulnerability",
        finding_fingerprint=fp_cache.compute_finding_fingerprint("vulnerability", "GET /x 501 Not Implemented leak"),
    )
    assert miss is None


def test_matches_scoped_by_target_glob():
    fp = fp_cache.compute_finding_fingerprint("vulnerability", "self-signed cert")
    fp_cache.add_pattern(target_glob="*.internal.test", finding_fingerprint=fp, finding_type="vulnerability")
    hit = fp_cache.matches(target="api.internal.test", finding_type="vulnerability", finding_fingerprint=fp)
    assert hit is not None
    # Same claim, different target scope — gated out by target_glob.
    miss = fp_cache.matches(target="external.example.com", finding_type="vulnerability", finding_fingerprint=fp)
    assert miss is None


def test_matches_scoped_by_finding_type():
    fp_cache.add_pattern(observation_signature="sig-nginx", finding_type="technology")
    hit = fp_cache.matches(target="x.test", finding_type="technology", observation_signatures=["sig-nginx"])
    assert hit is not None
    miss = fp_cache.matches(target="x.test", finding_type="vulnerability", observation_signatures=["sig-nginx"])
    assert miss is None


def test_matches_by_observation_signature_exact():
    fp_cache.add_pattern(observation_signature="sig-abc123")
    hit = fp_cache.matches(target="x.test", observation_signatures=["sig-abc123", "sig-other"])
    assert hit is not None
    miss = fp_cache.matches(target="x.test", observation_signatures=["sig-other"])
    assert miss is None


def test_observation_signature_pattern_ignores_fingerprint():
    """A signature-keyed pattern must NOT fall back to fingerprint matching —
    it is the precise matcher and only the exact signature triggers it."""
    fp_cache.add_pattern(observation_signature="sig-precise", finding_type="vulnerability")
    miss = fp_cache.matches(
        target="x.test", finding_type="vulnerability",
        finding_fingerprint=fp_cache.compute_finding_fingerprint("vulnerability", "x.test"),
        observation_signatures=["sig-different"],
    )
    assert miss is None


def test_remove_pattern():
    p = fp_cache.add_pattern(observation_signature="sig-noise")
    assert fp_cache.remove_pattern(p.id) is True
    assert fp_cache.list_patterns() == []
    assert fp_cache.remove_pattern(p.id) is False


def test_patterns_persist_across_reload():
    fp_cache.add_pattern(observation_signature="sig-persisted")
    fp_cache.reload()
    patterns = fp_cache.list_patterns()
    assert len(patterns) == 1
    assert patterns[0].observation_signature == "sig-persisted"
