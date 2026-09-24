"""Matcher-level tests for tech_dispatch signal rules.

Uses duck-typed finding stubs (finding_type.value / metadata / tags) so the
matcher can be exercised without a DB or engagement graph — the metadata
branches under test never touch the graph argument.
"""

from __future__ import annotations

from types import SimpleNamespace

from osprey.services.tech_dispatch import _matches


def _finding(ftype: str, meta: dict | None = None, tags: list | None = None):
    return SimpleNamespace(
        finding_type=SimpleNamespace(value=ftype),
        metadata=meta or {},
        tags=tags or [],
    )


def test_metadata_contains_any_matches_only_listed_values():
    rule = {"metadata_key": "technology", "metadata_contains_any": ["react", "vue", "angular"]}
    assert _matches(rule, [_finding("technology", {"technology": "React 18"})], None, "") is True
    # Regression: previously fired on ANY technology (existence-only fall-through).
    assert _matches(rule, [_finding("technology", {"technology": "Apache/2.4"})], None, "") is False


def test_metadata_contains_single_still_works():
    rule = {"metadata_key": "technology", "metadata_contains": "wordpress"}
    assert _matches(rule, [_finding("technology", {"technology": "WordPress 6"})], None, "") is True
    assert _matches(rule, [_finding("technology", {"technology": "Apache"})], None, "") is False


def test_metadata_existence_only_when_no_predicate():
    rule = {"metadata_key": "ip"}
    assert _matches(rule, [_finding("host", {"ip": "1.2.3.4"})], None, "") is True
    assert _matches(rule, [_finding("host", {})], None, "") is False


def test_metadata_value_exact_match():
    rule = {"metadata_key": "port", "metadata_value": "445"}
    assert _matches(rule, [_finding("port", {"port": "445"})], None, "") is True
    assert _matches(rule, [_finding("port", {"port": "80"})], None, "") is False


def test_finding_type_count_bounds():
    subs = [_finding("subdomain") for _ in range(3)]
    assert _matches({"finding_type": "subdomain", "min_count": 1, "max_count": 5}, subs, None, "") is True
    assert _matches({"finding_type": "subdomain", "max_count": 2}, subs, None, "") is False
