"""Root-cause fix for the ports-flag bug class.

Previously typed_recon_network.py pre-rendered ports= into a CLI flag string
folded into additional_args, so a tool's own build_command() (which expects
structured ports/top_ports params) laid its own flag on top of one already
present elsewhere in the command — naabu hit this with top-1000 collapsing
to a single IP, masscan hits it with a straight-up duplicate/garbled -p flag
plus zero shlex quoting on target/interface/router_mac/source_ip. The fix
makes the typed layer pass ports/top_ports through structurally and pushes
flag-rendering (and quoting) into each tool's own builder — the one place
that can guarantee exactly one port-selection flag.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from osprey.services.command_builder import build_command_for_tool

_TYPED_RECON_NETWORK = (
    Path(__file__).resolve().parents[2] / "platform-mcp" / "typed_recon_network.py"
)


def _load_typed_recon_network():
    spec = importlib.util.spec_from_file_location("_typed_recon_network_test", _TYPED_RECON_NETWORK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_typed = _load_typed_recon_network()


# --- typed_recon_network._normalize_ports_value: value-normalizer, no flag rendering ---

def test_normalize_ports_value_empty():
    assert _typed._normalize_ports_value("") == ("", "")


def test_normalize_ports_value_plain_list_passthrough():
    assert _typed._normalize_ports_value("22,443") == ("22,443", "")


def test_normalize_ports_value_strips_mistaken_prefix():
    assert _typed._normalize_ports_value("-p 22,443") == ("22,443", "")
    assert _typed._normalize_ports_value("--ports 22,443") == ("22,443", "")


def test_normalize_ports_value_top_n_classified_as_top_ports_not_ports():
    for raw in ("top-1000", "top_1000", "top 1000", "TOP-1000"):
        assert _typed._normalize_ports_value(raw) == ("", "1000")


# --- masscan_high_speed: exactly one -p flag, everything shell-quoted ---

def test_masscan_explicit_ports_single_flag():
    cmd = build_command_for_tool("masscan_high_speed", {"target": "10.0.0.5", "ports": "80,443"})
    assert cmd.count("-p") == 1
    assert "-p80,443" in cmd


def test_masscan_default_ports_when_absent():
    cmd = build_command_for_tool("masscan_high_speed", {"target": "10.0.0.5"})
    assert cmd.count("-p") == 1
    assert "-p1-65535" in cmd


def test_masscan_quotes_target_and_interface():
    # A space/glob in a param value isn't blocked by param_validator's shell-
    # metachar list (that only covers ;|&`$()<>) — word-splitting or glob
    # expansion once this command reaches `bash -c` is exactly the residual
    # gap this fix closes, so the builder itself must quote it.
    cmd = build_command_for_tool(
        "masscan_high_speed",
        {"target": "10.0.0.5", "interface": "eth0 *"},
    )
    assert "-e 'eth0 *'" in cmd


# --- naabu_port_scan: top-N and explicit ports both render exactly one flag ---

def test_naabu_top_n_shorthand_single_flag():
    cmd = build_command_for_tool("naabu_port_scan", {"target": "10.0.0.5", "ports": "top-1000"})
    assert cmd.count("-top-ports") == 1
    assert cmd.count("-p ") == 0


def test_naabu_structural_top_ports_single_flag():
    cmd = build_command_for_tool("naabu_port_scan", {"target": "10.0.0.5", "top_ports": "1000"})
    assert cmd.count("-top-ports") == 1


def test_naabu_explicit_ports_single_flag():
    cmd = build_command_for_tool("naabu_port_scan", {"target": "10.0.0.5", "ports": "80,443"})
    assert cmd.count("-p ") == 1


# --- nmap family: structural top_ports renders --top-ports exactly once ---

def test_nmap_service_scan_structural_top_ports():
    cmd = build_command_for_tool("nmap_service_scan", {"target": "10.0.0.5", "top_ports": "1000"})
    assert cmd.count("--top-ports") == 1
    assert " -p " not in cmd


def test_nmap_service_scan_explicit_ports_single_flag():
    cmd = build_command_for_tool("nmap_service_scan", {"target": "10.0.0.5", "ports": "80,443"})
    assert cmd.count(" -p ") == 1
    assert "--top-ports" not in cmd
