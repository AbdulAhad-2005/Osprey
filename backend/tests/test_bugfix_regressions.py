"""Regressions for engagement-report bugs (no DB / TestClient needed).

Each guards a specific real defect confirmed from live-engagement feedback.
"""

from __future__ import annotations

import sys
from pathlib import Path

from pentest_platform.services.command_builder import build_command_for_tool
from pentest_platform.services.ingest_promoter import _STRUCTURAL_RULE_IDS, _tool_has_parser
from pentest_platform.services.parsers.recon_network import _extract_unique_urls, _is_junk_url

# js_recon CLI is stdlib-only; import it directly for secret-regex checks.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp-servers" / "recon" / "tools"))
import _js_recon_cli as jr  # noqa: E402


def test_nmap_comma_separated_targets_become_space_separated():
    # Was: whole comma string handed to nmap as one host → "Failed to resolve".
    cmd = build_command_for_tool("nmap_service_scan", {"target": "1.2.3.4,5.6.7.8"})
    assert "1.2.3.4 5.6.7.8" in cmd
    cmd2 = build_command_for_tool("nmap_custom_scan", {"target": "1.1.1.1, 2.2.2.2", "flags": "-sT"})
    assert "1.1.1.1 2.2.2.2" in cmd2


def test_junk_archive_urls_are_filtered():
    assert _is_junk_url("http://www.tourism.gov.pk:80/%22target=%22_blank")
    assert _is_junk_url("http://h/x/%20onmousedown=alert(1)")
    assert _is_junk_url("http://h/%3cscript%3e")
    assert not _is_junk_url("https://api.example.com/v1/users?id=5")
    corpus = (
        "https://good.example.com/api\n"
        'http://x.example.com/%22target=%22_blank\n'
        "https://good.example.com/login\n"
    )
    urls = _extract_unique_urls(corpus)
    assert all("%22" not in u for u in urls)
    assert "https://good.example.com/api" in urls


def test_sendgrid_key_recognized_as_high_signal():
    # Replace with a valid SendGrid API key for testing
    key = <SENDGRID_API_KEY>
    secs = jr._extract_secrets(f'const k="{key}";', "app.js")
    sg = [s for s in secs if s["type"] == "sendgrid_api_key"]
    assert sg and sg[0]["high_signal"] is True


def test_ingest_structural_rules_skipped_only_for_parsed_tools():
    # Tools with a dedicated parser own their extraction; loose rules would add
    # garbage ("Service banner: mysql 8080", "TLS issuer: <webpack fragment>").
    assert _tool_has_parser("js_recon")
    assert _tool_has_parser("nmap_service_scan")
    assert _tool_has_parser("tech_stack_analyze")
    assert not _tool_has_parser("shell:curl")
    assert not _tool_has_parser("nikto_scan")  # no parser → keep all rules
    assert "version_banner" in _STRUCTURAL_RULE_IDS
    assert "certificate_issuer" in _STRUCTURAL_RULE_IDS


def test_ffuf_and_feroxbuster_use_bundled_wordlist_and_skip_tls():
    ferox = build_command_for_tool("feroxbuster_scan", {"url": "https://t"})
    assert "_wordlists/common-web.txt" in ferox and " -k" in ferox
    ffuf = build_command_for_tool("ffuf_scan", {"url": "https://t", "mode": "directory"})
    assert "_wordlists/common-web.txt" in ffuf and " -k" in ffuf
