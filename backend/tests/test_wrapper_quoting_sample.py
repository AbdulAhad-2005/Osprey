"""Unquoted-interpolation sweep (Fix 3) — spot-check a representative sample
of the 34 non-priority wrappers the sweep touched, across categories
(network/AD, recon, vuln, web) and across single-flag vs multi-branch
builders. See test_wrapper_quoting_priority.py for the 7 priority wrappers.
"""

from __future__ import annotations

from osprey.services.command_builder import build_command_for_tool

_TRICKY = "foo bar's *"
_QUOTED = "'foo bar'\"'\"'s *'"


def test_enum4linux_ng_advanced_quotes_target_and_domain():
    cmd = build_command_for_tool(
        "enum4linux_ng_advanced", {"target": _TRICKY, "domain": _TRICKY}
    )
    assert f"enum4linux-ng {_QUOTED}" in cmd
    assert f"-d {_QUOTED}" in cmd


def test_smbmap_quotes_target_and_domain():
    cmd = build_command_for_tool("smbmap_scan", {"target": _TRICKY, "domain": _TRICKY})
    assert f"-H {_QUOTED}" in cmd
    assert f"-d {_QUOTED}" in cmd


def test_zap_scan_quotes_host_port_and_target():
    cmd = build_command_for_tool(
        "zap_scan", {"daemon": True, "host": _TRICKY, "port": _TRICKY}
    )
    assert f"-host {_QUOTED}" in cmd
    assert f"-port {_QUOTED}" in cmd

    cmd2 = build_command_for_tool("zap_scan", {"daemon": False, "target": _TRICKY})
    assert f"-quickurl {_QUOTED}" in cmd2


def test_dalfox_quotes_url():
    cmd = build_command_for_tool("dalfox_xss_scan", {"url": _TRICKY})
    assert f"dalfox url {_QUOTED}" in cmd


def test_arjun_scan_quotes_url():
    cmd = build_command_for_tool("arjun_scan", {"url": _TRICKY})
    assert _QUOTED in cmd


def test_amass_scan_quotes_domain():
    cmd = build_command_for_tool("amass_scan", {"domain": _TRICKY})
    assert _QUOTED in cmd
