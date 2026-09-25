"""Regression: tools whose CLI wrapper accepts an alternate param in place of
the canonical primary (target/domain/url) must not be rejected by the
pre-execution validator when only the alternate is supplied.

Live bug: /fast-scan called subdomain_takeover_check(mode="list",
subdomains=...) with an empty target (valid per the tool's own build_command,
which only requires target OR subdomains) and got rejected with "Missing
primary param(s): target" before ever reaching the CLI.
"""

from __future__ import annotations

from osprey.services.param_validator import validate_raw


def test_subdomain_takeover_check_accepts_subdomains_without_target() -> None:
    result = validate_raw(
        "subdomain_takeover_check",
        {"target": "", "mode": "list", "subdomains": "www.example.com\nmail.example.com"},
    )
    assert result.approved, result.reason


def test_subdomain_takeover_check_rejects_when_neither_given() -> None:
    result = validate_raw("subdomain_takeover_check", {"mode": "list"})
    assert not result.approved
    assert "target" in result.reason


def test_dnsx_resolve_accepts_target_file_without_target() -> None:
    result = validate_raw("dnsx_resolve", {"target_file": "/tmp/hosts.txt"})
    assert result.approved, result.reason


def test_dnsx_reverse_accepts_target_file_without_target() -> None:
    result = validate_raw("dnsx_reverse", {"target_file": "/tmp/ips.txt"})
    assert result.approved, result.reason


def test_unaffected_tool_still_requires_its_primary() -> None:
    result = validate_raw("nmap_custom_scan", {"flags": "-sV"})
    assert not result.approved
    assert "target" in result.reason
