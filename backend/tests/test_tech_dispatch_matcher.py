"""Matcher-level tests for tech_dispatch signal rules.

Since plan 19 Phase 2, ``_matches`` reads OBSERVATIONS (type.value / details /
tags / target), not findings — the no-LLM path never creates structural
findings, so dispatch keys off the observations a tool run actually produced
(plans/harness/19a). Uses duck-typed observation stubs so the matcher can be
exercised without a DB or engagement graph — the ``details`` branches under
test never touch the graph argument.

``scope: per_match`` semantics (Plan 18 Workstream B) are preserved: a rule
returns exactly the observations that satisfied its clause so the caller can
attach the real per-host subject instead of always dispatching to the seed.
"""

from __future__ import annotations

from types import SimpleNamespace

from osprey.services.tech_dispatch import _matches, _observation_field


def _obs(otype: str, details: dict | None = None, tags: list | None = None, target: str = ""):
    return SimpleNamespace(
        type=SimpleNamespace(value=otype),
        details=details or {},
        tags=tags or [],
        target=target,
    )


def test_metadata_contains_any_matches_only_listed_values():
    rule = {"metadata_key": "technology", "metadata_contains_any": ["react", "vue", "angular"]}
    assert _matches(rule, [_obs("technology", {"technology": "React 18"})], None, "")[0] is True
    # Regression: previously fired on ANY technology (existence-only fall-through).
    assert _matches(rule, [_obs("technology", {"technology": "Apache/2.4"})], None, "")[0] is False


def test_metadata_contains_single_still_works():
    rule = {"metadata_key": "technology", "metadata_contains": "wordpress"}
    assert _matches(rule, [_obs("technology", {"technology": "WordPress 6"})], None, "")[0] is True
    assert _matches(rule, [_obs("technology", {"technology": "Apache"})], None, "")[0] is False


def test_metadata_existence_only_when_no_predicate():
    rule = {"metadata_key": "ip"}
    assert _matches(rule, [_obs("host", {"ip": "1.2.3.4"})], None, "")[0] is True
    assert _matches(rule, [_obs("host", {})], None, "")[0] is False


def test_metadata_value_exact_match():
    rule = {"metadata_key": "port", "metadata_value": "445"}
    assert _matches(rule, [_obs("port", {"port": "445"})], None, "")[0] is True
    assert _matches(rule, [_obs("port", {"port": "80"})], None, "")[0] is False


def test_finding_type_count_bounds():
    subs = [_obs("subdomain") for _ in range(3)]
    assert _matches({"finding_type": "subdomain", "min_count": 1, "max_count": 5}, subs, None, "")[0] is True
    assert _matches({"finding_type": "subdomain", "max_count": 2}, subs, None, "")[0] is False


def test_scope_not_per_match_never_returns_subjects():
    """The default (no ``scope`` declared) keeps engagement-wide/seed-scoped
    dispatch: matched or not, but never a per-observation subject list."""
    obs = [
        _obs("technology", {"technology": "WordPress"}, target="a.example.test"),
        _obs("technology", {"technology": "WordPress"}, target="b.example.test"),
    ]
    matched, per_match = _matches({"metadata_key": "technology", "metadata_contains": "wordpress"}, obs, None, "")
    assert matched is True
    assert per_match == []


def test_scope_per_match_returns_every_satisfying_observation():
    obs = [
        _obs("technology", {"technology": "WordPress"}, target="a.example.test"),
        _obs("technology", {"technology": "WordPress"}, target="b.example.test"),
        _obs("technology", {"technology": "Apache"}, target="c.example.test"),
    ]
    rule = {"metadata_key": "technology", "metadata_contains": "wordpress", "scope": "per_match"}
    matched, per_match = _matches(rule, obs, None, "")
    assert matched is True
    assert {o.target for o in per_match} == {"a.example.test", "b.example.test"}


def test_observation_field_reads_target_title_and_details():
    o = _obs("email", details={"domain": "example.test", "title": "user@example.test"}, target="user@example.test")
    assert _observation_field(o, "title") == "user@example.test"
    assert _observation_field(o, "target") == "user@example.test"
    assert _observation_field(o, "domain") == "example.test"
    assert _observation_field(o, "missing_field") == ""
