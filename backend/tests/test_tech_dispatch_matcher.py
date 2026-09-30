"""Matcher-level tests for tech_dispatch signal rules.

Uses duck-typed finding stubs (finding_type.value / metadata / tags / title /
target) so the matcher can be exercised without a DB or engagement graph —
the metadata branches under test never touch the graph argument.

Plan 18 Workstream B: ``_matches`` now returns ``(matched, per_match_findings)``
instead of a bare bool — a rule declaring ``scope: per_match`` needs the
caller (``suggest_dispatch``) to know exactly which findings satisfied the
clause, so it can attach the real per-host subject instead of silently
always dispatching to the engagement seed.
"""

from __future__ import annotations

from types import SimpleNamespace

from osprey.services.tech_dispatch import _finding_field, _matches, suggest_dispatch


def _finding(ftype: str, meta: dict | None = None, tags: list | None = None, title: str = "", target: str = ""):
    return SimpleNamespace(
        finding_type=SimpleNamespace(value=ftype),
        metadata=meta or {},
        tags=tags or [],
        title=title,
        target=target,
    )


def test_metadata_contains_any_matches_only_listed_values():
    rule = {"metadata_key": "technology", "metadata_contains_any": ["react", "vue", "angular"]}
    assert _matches(rule, [_finding("technology", {"technology": "React 18"})], None, "")[0] is True
    # Regression: previously fired on ANY technology (existence-only fall-through).
    assert _matches(rule, [_finding("technology", {"technology": "Apache/2.4"})], None, "")[0] is False


def test_metadata_contains_single_still_works():
    rule = {"metadata_key": "technology", "metadata_contains": "wordpress"}
    assert _matches(rule, [_finding("technology", {"technology": "WordPress 6"})], None, "")[0] is True
    assert _matches(rule, [_finding("technology", {"technology": "Apache"})], None, "")[0] is False


def test_metadata_existence_only_when_no_predicate():
    rule = {"metadata_key": "ip"}
    assert _matches(rule, [_finding("host", {"ip": "1.2.3.4"})], None, "")[0] is True
    assert _matches(rule, [_finding("host", {})], None, "")[0] is False


def test_metadata_value_exact_match():
    rule = {"metadata_key": "port", "metadata_value": "445"}
    assert _matches(rule, [_finding("port", {"port": "445"})], None, "")[0] is True
    assert _matches(rule, [_finding("port", {"port": "80"})], None, "")[0] is False


def test_finding_type_count_bounds():
    subs = [_finding("subdomain") for _ in range(3)]
    assert _matches({"finding_type": "subdomain", "min_count": 1, "max_count": 5}, subs, None, "")[0] is True
    assert _matches({"finding_type": "subdomain", "max_count": 2}, subs, None, "")[0] is False


def test_scope_not_per_match_never_returns_findings():
    """The default (no ``scope`` declared) keeps its exact pre-Plan-18
    behavior: matched or not, but never a per-finding subject list — this is
    what keeps every un-annotated rule's dispatch engagement-wide/seed-scoped,
    unchanged."""
    findings = [
        _finding("technology", {"technology": "WordPress"}, target="a.example.test"),
        _finding("technology", {"technology": "WordPress"}, target="b.example.test"),
    ]
    matched, per_match = _matches({"metadata_key": "technology", "metadata_contains": "wordpress"}, findings, None, "")
    assert matched is True
    assert per_match == []


def test_scope_per_match_returns_every_satisfying_finding():
    findings = [
        _finding("technology", {"technology": "WordPress"}, target="a.example.test"),
        _finding("technology", {"technology": "WordPress"}, target="b.example.test"),
        _finding("technology", {"technology": "Apache"}, target="c.example.test"),
    ]
    rule = {"metadata_key": "technology", "metadata_contains": "wordpress", "scope": "per_match"}
    matched, per_match = _matches(rule, findings, None, "")
    assert matched is True
    assert {f.target for f in per_match} == {"a.example.test", "b.example.test"}


def test_finding_field_reads_top_level_and_metadata():
    f = _finding("email", meta={"domain": "example.test"}, title="user@example.test", target="user@example.test")
    assert _finding_field(f, "title") == "user@example.test"
    assert _finding_field(f, "target") == "user@example.test"
    assert _finding_field(f, "domain") == "example.test"
    assert _finding_field(f, "missing_field") == ""
