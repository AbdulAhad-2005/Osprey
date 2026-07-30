"""Tests for the Part-3 active-recon capability wiring.

Content discovery (feroxbuster/ffuf/gobuster), parameter discovery (arjun +
passive URL mining), JS-aware crawl (katana), the js_recon analyzer, and the
surface-completeness probes (email posture, well-known/robots). Verifies real
tool output becomes correctly-typed/graded findings and that the attack-surface
handoff tags (injection_point_candidate / interesting_path / js-secret) are set.
"""

from __future__ import annotations

import json

from pentest_platform.schemas.finding import ClaimSeverity, EvidenceGrade, FindingType
from pentest_platform.services.command_builder import build_command_for_tool
from pentest_platform.services.parsers.registry import ensure_parsers_loaded, parse_tool_output
from pentest_platform.services.tool_registry import get_tool_definition, resolve_tool_name

ensure_parsers_loaded()


def _parse(tool, out, target=""):
    return parse_tool_output(tool, out, engagement_id="e1", run_id="r1", target=target)


# ---- registration / command building -------------------------------------

def test_new_recon_tools_are_registered():
    for name in ("js_recon", "email_security_probe", "well_known_probe"):
        assert get_tool_definition(name) is not None, name
    # web wrappers resolve too
    for name in ("feroxbuster_scan", "ffuf_scan", "arjun_scan", "katana_crawl"):
        assert get_tool_definition(name) is not None, name


def test_ffuf_builds_one_coherent_command_per_mode():
    # Regression: the harvested wrapper emitted four conflicting -u flags.
    for mode, marker in (("directory", "/FUZZ"), ("vhost", "Host: FUZZ"), ("parameter", "FUZZ=")):
        cmd = build_command_for_tool("ffuf_scan", {"url": "https://t", "mode": mode})
        assert cmd.count(" -u ") == 1, f"{mode}: {cmd}"
        assert marker in cmd


def test_js_recon_command_targets_bundled_cli():
    cmd = build_command_for_tool("js_recon", {"target": "https://t"})
    assert "_js_recon_cli.py" in cmd and "--target" in cmd


# ---- content discovery ----------------------------------------------------

def test_feroxbuster_ndjson():
    out = "\n".join([
        json.dumps({"type": "response", "url": "https://t/admin", "status": 200, "content_length": 12}),
        json.dumps({"type": "response", "url": "https://t/api/v1/x", "status": 403, "content_length": 1}),
        json.dumps({"type": "statistics"}),
    ])
    fs = _parse("feroxbuster_scan", out, target="https://t")
    assert len(fs) == 2
    forbidden = next(f for f in fs if f.metadata["status"] == "403")
    assert "access_controlled" in forbidden.tags
    assert all(f.finding_type == FindingType.URL for f in fs)


def test_ffuf_ndjson_and_gobuster_text():
    ffuf = json.dumps({"input": {"FUZZ": "login"}, "status": 200, "length": 5, "url": "https://t/login"})
    assert _parse("ffuf_scan", ffuf, target="https://t")[0].metadata["url"] == "https://t/login"
    gob = _parse("gobuster_scan", "/admin (Status: 200) [Size: 9]", target="https://t")
    assert gob[0].metadata["url"] == "https://t/admin"


# ---- parameter discovery + handoff tags ----------------------------------

def test_arjun_params_tagged_as_injection_points():
    fs = _parse("arjun_scan", "[+] Parameters found: id, redirect, debug", target="https://t/x")
    assert {f.metadata["parameter"] for f in fs} == {"id", "redirect", "debug"}
    assert all("injection_point_candidate" in f.tags for f in fs)


def test_katana_mines_urls_and_parameters():
    out = json.dumps({"request": {"endpoint": "https://t/api/orders?id=5&sort=asc"}})
    fs = _parse("katana_crawl", out, target="https://t")
    params = {f.metadata.get("parameter") for f in fs if f.finding_type == FindingType.OBSERVATION}
    assert params == {"id", "sort"}
    assert any(f.finding_type == FindingType.URL and "interesting_path" in f.tags for f in fs)


# ---- js_recon -------------------------------------------------------------

def test_js_recon_endpoints_secrets_cloud():
    out = json.dumps({
        "target": "https://t", "js_file_count": 1, "endpoint_count": 2,
        "endpoints": ["/api/v1/admin", "/health"],
        "secrets": [
            {"type": "aws_access_key_id", "match": "AKIA...", "secret": "AKIAZ7QW4RTY8UVBNMLK", "high_signal": True, "source": "a.js"},
            {"type": "jwt", "match": "eyJ...", "secret": "eyJ...", "high_signal": False, "source": "a.js"},
        ],
        "cloud_assets": [{"type": "s3_bucket_url", "bucket": "prod", "match": "prod.s3.amazonaws.com", "source": "a.js"}],
    })
    fs = _parse("js_recon", out, target="https://t")
    admin_ep = next(f for f in fs if f.title == "/api/v1/admin")
    assert "injection_point_candidate" in admin_ep.tags
    aws = next(f for f in fs if f.metadata.get("secret_type") == "aws_access_key_id")
    assert aws.claim_severity == ClaimSeverity.MEDIUM and "verify_validity" in aws.tags
    assert aws.evidence_grade == EvidenceGrade.OBSERVED
    assert any("cloud-asset" in f.tags for f in fs)


# ---- surface completeness -------------------------------------------------

def test_email_security_flags_missing_spf_dmarc():
    out = "=== MX ===\nNONE\n=== SPF ===\nNONE\n=== DMARC ===\nNONE\n=== DKIM ===\n=== DONE ==="
    fs = _parse("email_security_probe", out, target="example.com")
    weak = next(f for f in fs if "anti-spoofing" in f.title)
    assert weak.claim_severity == ClaimSeverity.LOW
    assert "SPF" in weak.metadata["missing"] and "DMARC" in weak.metadata["missing"]


def test_well_known_extracts_robots_disallow_as_leads():
    out = (
        "=== PATH /robots.txt ===\nSTATUS: 200\nUser-agent: *\nDisallow: /admin/\n"
        "Disallow: /internal/config\n=== DONE ==="
    )
    fs = _parse("well_known_probe", out, target="https://t")
    lead_urls = {f.target for f in fs if "robots_disallow" in f.tags}
    assert "https://t/admin/" in lead_urls
    assert any(f.metadata.get("disallow") for f in fs)
