"""Plan 19 — sqlmap must always run against a real, parameterized request.

CONFIRMED BUG (traced through the live param-normalization code, not
guessed): the dispatch rules handed sqlmap a bare host label
(``target="apiurdu.geo.tv"``), which normalizes to ``url="https://apiurdu.geo.tv"``
— no query string, nothing to inject into. sqlmap correctly finds nothing
against a URL with no parameter, which is exactly the "sqlmap gives empty
output" the operator hit. This is the textbook anti-pattern every real
pentester avoids: never run sqlmap against a bare domain root.

Two coordinated fixes:
  1. ``php_stack_injection_focus`` (dispatched sqlmap the moment PHP was
     detected, with no parameter at all) is DELETED — PHP-ness alone never
     implies an injectable request.
  2. ``injection_point_candidates`` (the one rule that fires on a REAL
     discovered parameter) now wires that parameter's actual URL through via
     ``params_from: {url: url}`` plus a conservative baseline profile
     (``--level=1 --risk=1``) — instead of falling back to the generic
     subject-label default.
  3. ``_param_observation`` (web_recon.py) now guarantees the parameter it
     reports actually appears in the URL it stores — synthesizing a test
     value when the source was active discovery (arjun/x8) rather than an
     already-parameterized archived URL (gau/wayback/katana).

This test proves the full chain end to end: a parser observation → the
dispatch rule → a suggestion sqlmap can actually use.
"""
from __future__ import annotations

from osprey.schemas.engagement import EngagementCreateRequest
from osprey.services.engagement_store import get_engagement_store
from osprey.services.observation_store import get_observation_store
from osprey.services.parsers.web_recon import extract_parameters_from_urls, parse_arjun
from osprey.services.tech_dispatch import suggest_dispatch


def _make_engagement(target: str) -> str:
    return get_engagement_store().create(EngagementCreateRequest(target=target)).id


def test_php_detection_alone_no_longer_dispatches_sqlmap():
    """The confirmed-broken trigger is gone: a technology observation with no
    discovered parameter must never produce an sqlmap suggestion."""
    from osprey.schemas.observation import Observation, ObservationType

    eid = _make_engagement("example.com")
    get_observation_store().record(Observation(
        engagement_id=eid, type=ObservationType.TECHNOLOGY, target="https://www.example.com",
        source_tool="tech_stack_analyze", details={"name": "PHP 7.4", "technology": "PHP 7.4", "hostname": "www.example.com"},
    ))
    suggestions = suggest_dispatch(engagement_id=eid)
    assert not any(s.default_tool == "sqlmap_scan" for s in suggestions)


def test_archived_parameterized_url_dispatches_sqlmap_with_the_real_url():
    """A parameter mined from an already-parameterized archived URL (gau/
    wayback/katana) must reach sqlmap as that exact real, testable URL."""
    eid = _make_engagement("example.com")
    real_url = "https://www.example.com/article.php?id=5"
    observations = extract_parameters_from_urls(
        [real_url], source_tool="gau_discovery", engagement_id=eid, run_id="", target="example.com",
    )
    assert observations, "extract_parameters_from_urls should have found the 'id' parameter"
    for obs in observations:
        get_observation_store().record(obs)

    suggestions = suggest_dispatch(engagement_id=eid)
    sqlmap_suggestions = [s for s in suggestions if s.default_tool == "sqlmap_scan"]
    assert sqlmap_suggestions, "a real parameterized URL must produce an sqlmap suggestion"
    assert any(s.params.get("url") == real_url for s in sqlmap_suggestions), (
        f"expected the real parameterized URL {real_url!r} in params, got: "
        f"{[s.params for s in sqlmap_suggestions]}"
    )
    assert all(s.additional_args == "--level=1 --risk=1" for s in sqlmap_suggestions)


def test_actively_discovered_parameter_gets_a_synthesized_testable_url():
    """arjun reports a parameter NAME against a bare endpoint with no query
    string yet — the observation must still carry a directly-testable URL
    (the parameter synthesized into it), not the bare endpoint alone."""
    bare_url = "https://www.example.com/search"
    observations = parse_arjun(
        "Parameters found: q, page",
        engagement_id="e1", run_id="", target=bare_url,
    )
    assert observations
    for obs in observations:
        param = obs.details["parameter"]
        url = obs.details["url"]
        assert f"{param}=" in url, f"parameter {param!r} must actually appear in {url!r}"
        assert url.startswith(bare_url)
    # Exactly one '?' — no double-appending across the two params.
    assert all(obs.details["url"].count("?") == 1 for obs in observations)


def test_gau_and_waybackurls_mine_parameters_from_their_own_url_output():
    """The dominant real-world source of parameterized requests (gau/
    waybackurls archives routinely surface thousands) must actually feed the
    injection-point pipeline — previously only katana_crawl did; gau/
    waybackurls/hakrawler produced plain URL observations and silently
    discarded every query parameter they returned."""
    from osprey.services.parsers.recon_network import parse_gau, parse_waybackurls

    stdout = "https://www.example.com/article.php?id=5\nhttps://www.example.com/about\n"
    for parser, tool in ((parse_gau, "gau_discovery"), (parse_waybackurls, "waybackurls_discovery")):
        observations = parser(stdout, engagement_id="e1", run_id="", target="example.com")
        injection_points = [o for o in observations if "injection_point_candidate" in (o.tags or [])]
        assert injection_points, f"{tool} must mine 'id' as an injection point from its own URL output"
        assert injection_points[0].details["parameter"] == "id"
        assert "id=5" in injection_points[0].details["url"]
        # The non-parameterized URL must never spawn a phantom injection point.
        assert all("about" not in ip.details["url"] for ip in injection_points)


def test_url_already_carrying_the_parameter_is_never_double_appended():
    from osprey.services.parsers.web_recon import _ensure_param_in_url

    url = "https://x.test/a?id=5&name=bob"
    assert _ensure_param_in_url(url, "id") == url
    assert _ensure_param_in_url(url, "page") == f"{url}&page=1"
