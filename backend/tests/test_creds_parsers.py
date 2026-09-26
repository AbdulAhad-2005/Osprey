"""Credential-harvesting parsers (IntelX, Resecurity) — turning breach-intel
JSON into typed CREDENTIAL/EMAIL/SUBDOMAIN observations.

Covers a real bug found and fixed during QA: a bare substring check
(`target in host`) misclassified an unrelated domain that merely contains the
target as text as a genuine subdomain — same false-surface class as the
earlier rDNS PTR-placeholder fix. Also covers the "never mask a leaked
credential" rule from AGENTS.md, graceful handling when the Identity/leaks
key isn't configured, and malformed input.

All targets, hostnames, usernames, and passwords below are synthetic
fixtures invented for these tests — none reference any real engagement,
organization, or person.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from osprey.schemas.observation import ObservationType
from osprey.services.parsers.creds import (
    credential_observations,
    parse_intelx,
    parse_resecurity,
)

_INTELX_CLI = Path(__file__).resolve().parents[2] / "mcp-servers" / "osint" / "tools" / "_intelx_cli.py"


def _load_intelx_cli():
    spec = importlib.util.spec_from_file_location("_intelx_cli_test", _INTELX_CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_intelx_cli = _load_intelx_cli()


def _by_type(obs, t):
    return [o for o in obs if o.type == t]


# --------------------------------------------------------------------------- #
# parse_intelx — phonebook (emails/domains)
# --------------------------------------------------------------------------- #

def test_phonebook_domain_substring_false_positive_is_fixed():
    data = {
        "mode": "phonebook", "term": "acme.io",
        "phonebook": {
            "emails": [],
            "domains": ["acme.ionews.com", "blog.acme.io", "acme.io", "notacme.io"],
            "urls": [],
        },
    }
    obs = parse_intelx(json.dumps(data), target="acme.io")
    hosts = {o.details["hostname"] for o in _by_type(obs, ObservationType.SUBDOMAIN)}
    assert hosts == {"blog.acme.io", "acme.io"}
    assert "acme.ionews.com" not in hosts  # contains target as substring, not a real subdomain
    assert "notacme.io" not in hosts       # same class: prefix collision, not a suffix match


def test_phonebook_emails_become_email_observations():
    # example.com is deliberately treated as a placeholder/noise domain by
    # is_valid_email (RFC 2606) — use a domain that isn't blocklisted so this
    # test exercises real extraction, not the placeholder filter.
    data = {
        "mode": "phonebook", "term": "acmecorp-test.io",
        "phonebook": {"emails": ["Alice@Acmecorp-Test.io", "not-an-email", "bob@acmecorp-test.io"],
                      "domains": [], "urls": []},
    }
    obs = parse_intelx(json.dumps(data), target="acmecorp-test.io")
    emails = sorted(o.details["email"] for o in _by_type(obs, ObservationType.EMAIL))
    assert emails == ["alice@acmecorp-test.io", "bob@acmecorp-test.io"]  # normalized, invalid dropped


def test_intelx_leaks_key_not_configured_yields_no_credentials_no_crash():
    """Mirrors what _intelx_cli.py actually returns when INTELX_IDENTITY_API_KEY
    is unset: {"credentials": [], "warning": "..."} — must parse cleanly to
    zero CREDENTIAL observations, not raise or silently invent anything."""
    data = {
        "mode": "all", "term": "example.com",
        "phonebook": {"emails": [], "domains": [], "urls": []},
        "leaks": {"credentials": [], "warning": "INTELX_IDENTITY_API_KEY not set — leaked-credential lookup skipped"},
    }
    obs = parse_intelx(json.dumps(data), target="example.com")
    assert _by_type(obs, ObservationType.CREDENTIAL) == []


def test_intelx_leaked_credential_password_is_never_masked():
    data = {
        "mode": "all", "term": "example.com",
        "phonebook": {"emails": [], "domains": [], "urls": []},
        "leaks": {"credentials": [{
            "username": "admin", "password": "S3cr3t!Plain", "email": "admin@example.com",
            "host": "portal.example.com", "source": "breach-2023",
        }]},
    }
    obs = parse_intelx(json.dumps(data), target="example.com")
    creds = _by_type(obs, ObservationType.CREDENTIAL)
    assert len(creds) == 1
    assert creds[0].details["password"] == "S3cr3t!Plain"  # intact, not redacted/hashed
    assert creds[0].details["source_class"] == "breach_db"
    assert creds[0].details["hostname"] == "portal.example.com"


def test_intelx_malformed_json_returns_empty_not_raise():
    assert parse_intelx("not json at all") == []
    assert parse_intelx("") == []
    assert parse_intelx(json.dumps([1, 2, 3])) == []  # valid JSON, wrong shape (list not dict)


# --------------------------------------------------------------------------- #
# parse_resecurity
# --------------------------------------------------------------------------- #

def test_resecurity_credentials_and_emails():
    data = {
        "target": "acmecorp-test.io",
        "credentials": [{"username": "root", "password": "hunter2", "host": "vpn.acmecorp-test.io"}],
        "emails": ["carol@acmecorp-test.io"],
    }
    obs = parse_resecurity(json.dumps(data), target="acmecorp-test.io")
    creds = _by_type(obs, ObservationType.CREDENTIAL)
    emails = _by_type(obs, ObservationType.EMAIL)
    assert creds[0].details["password"] == "hunter2"
    assert creds[0].details["provider"] == "resecurity"
    assert any(e.details["email"] == "carol@acmecorp-test.io" for e in emails)


def test_resecurity_malformed_json_returns_empty_not_raise():
    assert parse_resecurity("{not valid") == []
    assert parse_resecurity(json.dumps("just a string")) == []


# --------------------------------------------------------------------------- #
# credential_observations — the shared normalizer both parsers (and the
# private creds-manager overlay) reuse
# --------------------------------------------------------------------------- #

def test_credential_observations_deduplicates_identical_records():
    records = [
        {"username": "admin", "password": "pw1", "host": "x.test"},
        {"username": "admin", "password": "pw1", "host": "x.test"},  # exact duplicate
        {"username": "admin", "password": "pw2", "host": "x.test"},  # different password — kept
    ]
    obs = credential_observations(records, tool="intelx_scan", provider="intelx", source_class="breach_db")
    assert len(_by_type(obs, ObservationType.CREDENTIAL)) == 2


def test_credential_observations_skips_records_missing_password_or_identity():
    records = [
        {"username": "admin"},                    # no password
        {"password": "pw"},                        # no username/email
        {"username": "", "email": "", "password": "pw"},  # blank identity
    ]
    assert credential_observations(records, tool="t", provider="p", source_class="breach_db") == []


def test_credential_observations_derives_email_from_username_when_email_shaped():
    records = [{"username": "dave@acmecorp-test.io", "password": "pw"}]
    obs = credential_observations(records, tool="t", provider="p", source_class="breach_db")
    creds = _by_type(obs, ObservationType.CREDENTIAL)
    emails = _by_type(obs, ObservationType.EMAIL)
    assert creds[0].details["email"] == "dave@acmecorp-test.io"
    assert any(e.details["email"] == "dave@acmecorp-test.io" for e in emails)


def test_credential_observations_host_falls_back_to_target_when_no_host_in_record():
    records = [{"username": "admin", "password": "pw"}]  # no host/url field at all
    obs = credential_observations(records, tool="t", provider="p", source_class="breach_db", target="fallback.test")
    creds = _by_type(obs, ObservationType.CREDENTIAL)
    assert creds[0].target == "fallback.test"  # never orphaned without a target link


# --------------------------------------------------------------------------- #
# _extract_url_combo (_intelx_cli.py) — real bug found and fixed during QA:
# IntelX's phonebook "urls" bucket mixes genuine credential-stuffing combo
# lines ("url:identity:password") in with ordinary URLs AND URL-encoded
# search-spam that happens to contain colons too. The shapes below mirror
# what live QA testing against a real engagement target observed (target,
# hostnames, usernames and passwords replaced with synthetic fixtures here) —
# before this fix, genuine leaked credentials were extracted from the API
# correctly, then silently discarded (classified as harmless "urls", which
# the backend parser never even read). Getting the spam side wrong would be
# worse than dropping data: a fabricated CREDENTIAL finding from spam text is
# an evidence-integrity violation, not just a missed one.
# --------------------------------------------------------------------------- #

def test_extract_url_combo_email_identity():
    combo = _intelx_cli._extract_url_combo(
        "https://acmewidgets.io/portal/login.php:jane.doe@webmail.test:Tr0ub4dor&3"
    )
    assert combo == {
        "url": "https://acmewidgets.io/portal/login.php",
        "username": "", "email": "jane.doe@webmail.test", "password": "Tr0ub4dor&3",
    }


def test_extract_url_combo_username_identity():
    combo = _intelx_cli._extract_url_combo("https://acmewidgets.io/logon:alexrivera123:Xk9mPqZ2v")
    assert combo == {
        "url": "https://acmewidgets.io/logon",
        "username": "alexrivera123", "email": "", "password": "Xk9mPqZ2v",
    }


def test_extract_url_combo_rejects_percent_encoded_spam():
    # Synthetic spam sample: URL-encoded non-Latin ad/gambling text that
    # happens to contain colons, mixed into the exact same "urls" bucket as
    # genuine leaks (this shape, minus the target, mirrors what was observed
    # live during QA).
    spam = (
        "https://acmewidgets.io/search/%EC%97%AC%EC%88%98%ED%99%88%ED%83%80%EC%9D%B4"
        "%EB%95%80%EB%95%A1%E3%80%90katalk:za33%E3%80%91%EC%95%84%EC%82%B0"
        "%EC%B6%9C%EC%9E%A5%EB%A7%8C%EB%82%A8:www.spamsite.test"
    )
    assert _intelx_cli._extract_url_combo(spam) is None


def test_extract_url_combo_rejects_plain_url_no_combo():
    assert _intelx_cli._extract_url_combo("https://acmewidgets.io/about-us") is None


def test_extract_url_combo_rejects_url_with_port_not_combo():
    # A port number is one extra colon beyond the scheme — must not be
    # misread as a 1-segment "combo" (needs >= 2 segments past the URL).
    assert _intelx_cli._extract_url_combo("https://acmewidgets.io:8443/portal") is None


def test_extract_url_combo_rejects_empty_or_oversized_segments():
    assert _intelx_cli._extract_url_combo("https://host/path::") is None  # empty segments
    long_junk = "x" * 200
    assert _intelx_cli._extract_url_combo(f"https://host/path:{long_junk}:pw") is None


def test_phonebook_credentials_field_populated_and_urls_bucket_excludes_them(monkeypatch):
    """End-to-end through phonebook() itself (network mocked): a combo-shaped
    selector lands in "credentials", a spam-shaped one and a plain URL both
    stay out of it."""
    monkeypatch.setattr(_intelx_cli, "_search_key", lambda: "test-key")
    monkeypatch.setattr(_intelx_cli, "_request", lambda *a, **k: {"id": "search123"})

    def _fake_poll(base, path, search_id, key, *, limit, results_field):
        return [
            {"selectorvalue": "https://acmewidgets.io/logon:alexrivera123:Xk9mPqZ2v"},
            {"selectorvalue": "https://acmewidgets.io/search/%E3%80%90katalk:za33%E3%80%91:www.spamsite.test"},
            {"selectorvalue": "https://acmewidgets.io/about-us"},
            {"selectorvalue": "contact@acmewidgets.io"},
        ]

    monkeypatch.setattr(_intelx_cli, "_poll", _fake_poll)
    result = _intelx_cli.phonebook("acmewidgets.io", 50)
    assert len(result["credentials"]) == 1
    assert result["credentials"][0]["username"] == "alexrivera123"
    # Only the genuine combo is pulled out of "urls" — the spam selector is
    # correctly REJECTED as a combo (percent-encoded), but that only means it
    # falls through to the harmless urls bucket same as before the fix, not
    # that it vanishes. The design goal is "never fabricate a fake credential
    # from it", not "make spam disappear from the urls list".
    assert result["urls"] == [
        "https://acmewidgets.io/search/%E3%80%90katalk:za33%E3%80%91:www.spamsite.test",
        "https://acmewidgets.io/about-us",
    ]
    assert result["emails"] == ["contact@acmewidgets.io"]


def test_parse_intelx_reads_phonebook_credentials_end_to_end():
    """The other half of the fix: the backend parser must actually read the
    new phonebook.credentials field, not just the CLI producing it."""
    data = {
        "provider": "intelx", "mode": "all", "term": "acmewidgets.io",
        "phonebook": {
            "emails": [], "domains": [], "urls": [],
            "credentials": [{
                "url": "https://acmewidgets.io/logon", "username": "alexrivera123",
                "email": "", "password": "Xk9mPqZ2v",
            }],
        },
        "leaks": {"credentials": []},
    }
    obs = parse_intelx(json.dumps(data), target="acmewidgets.io")
    creds = _by_type(obs, ObservationType.CREDENTIAL)
    assert len(creds) == 1
    assert creds[0].details["password"] == "Xk9mPqZ2v"  # intact, never masked
    assert creds[0].details["username"] == "alexrivera123"
    assert creds[0].details["hostname"] == "acmewidgets.io"
