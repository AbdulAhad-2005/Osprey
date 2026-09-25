"""nmap host-timeout scaling + privileged-scan reachability.

Root cause of a real failed run: `nmap_script_bound_args` injected a flat
`--host-timeout 90s` whenever -sC/--script was present, regardless of scan
shape — a full `-sV -sC -p-` sweep against a rate-limited CDN edge needs far
longer than 90s just to get through the port sweep, so nmap killed every
single host with "Host timed out" before producing anything. Separately,
`nmap_syn_scan` is requires_root=True (always real root via docker exec -u 0,
or `sudo` natively) but the command builder still rendered an unprivileged
-sT/--unprivileged fallback since nothing ever set the separate `privileged`
param — throwing away root access the execution layer already grants.

The command-building logic these tests exercise used to live only in the
backend's command_builder.py, reachable exclusively through the docker-exec
path — the reason nmap alone (of ~120 tools) didn't work in native/no-Docker
mode. It now lives in mcp-servers/network/tools/_nmap_common.py + the four
nmap_*.py wrappers, loaded the same way every other tool's build_command is
(backend/src/osprey/services/command_builder.build_command_for_tool ->
_load_build_command), so the public build_command_for_tool() tests below are
unchanged; only the two direct-function tests move to the new location.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from osprey.services.command_builder import build_command_for_tool

_NMAP_COMMON_PATH = (
    Path(__file__).resolve().parents[2] / "mcp-servers" / "network" / "tools" / "_nmap_common.py"
)


def _load_nmap_common():
    spec = importlib.util.spec_from_file_location("_nmap_common_test", _NMAP_COMMON_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_nc = _load_nmap_common()
nmap_flags_cover_wide_range = _nc.nmap_flags_cover_wide_range
nmap_script_bound_args = _nc.nmap_script_bound_args


# --- nmap_flags_cover_wide_range: detects a full/wide port selection ---

def test_wide_range_detects_dash_p_dash():
    assert nmap_flags_cover_wide_range("-sV -sC -p-") is True


def test_wide_range_detects_explicit_full_range():
    assert nmap_flags_cover_wide_range("-sV -sC -p 1-65535") is True


def test_wide_range_false_for_narrow_ports():
    assert nmap_flags_cover_wide_range("-sV -sC -p 80,443") is False


def test_wide_range_false_when_no_ports_flag_at_all():
    assert nmap_flags_cover_wide_range("-sV -sC") is False


# --- nmap_script_bound_args: scaling + override + opt-out ---

def test_bound_args_narrow_scan_keeps_short_defaults():
    args = " ".join(nmap_script_bound_args("-sV -sC -p 80,443"))
    assert "--host-timeout 90s" in args
    assert "--script-timeout 20s" in args


def test_bound_args_wide_scan_gets_much_larger_defaults():
    args = " ".join(nmap_script_bound_args("-sV -sC -p-"))
    assert "--host-timeout 3600s" in args
    assert "--script-timeout 300s" in args


def test_bound_args_explicit_override_used_verbatim():
    args = " ".join(nmap_script_bound_args("-sV -sC -p-", host_timeout="45m"))
    assert "--host-timeout 45m" in args


def test_bound_args_unlimited_opt_out_omits_the_flag():
    for value in ("none", "0", "unlimited", "off", "0s"):
        args = nmap_script_bound_args("-sV -sC -p-", host_timeout=value)
        assert "--host-timeout" not in args


def test_bound_args_respects_caller_supplied_host_timeout_flag():
    # If the caller already put --host-timeout in the flags string, don't
    # double it, regardless of scan shape or an override param.
    args = nmap_script_bound_args("-sV -sC -p- --host-timeout 5m", host_timeout="1h")
    assert "--host-timeout" not in args


# --- nmap_syn_scan: always privileged (requires_root=True), never falls back ---

def test_nmap_syn_scan_always_uses_real_syn_scan():
    cmd = build_command_for_tool("nmap_syn_scan", {"target": "10.0.0.5"})
    assert "-sS" in cmd
    assert "-sT" not in cmd
    assert "--unprivileged" not in cmd
    assert "sudo" not in cmd


# --- nmap_custom_scan: always privileged (requires_root=True), no per-call
# param needed, no sudo prefix in the *command string* (docker exec -u 0, or
# the wrapper's own sudo=True to _core.runner.run_tool, is the privilege
# boundary — never baked into the command text itself) ---

def test_nmap_custom_scan_always_privileged_regardless_of_param():
    for extra_params in ({}, {"privileged": False}, {"privileged": True}):
        cmd = build_command_for_tool(
            "nmap_custom_scan", {"target": "10.0.0.5", "flags": "-sS -O", **extra_params}
        )
        assert "-sS" in cmd
        assert "--unprivileged" not in cmd
        assert not cmd.startswith("sudo")


def test_nmap_custom_scan_defaults_to_real_syn_scan_with_no_scan_type_given():
    cmd = build_command_for_tool("nmap_custom_scan", {"target": "10.0.0.5", "flags": ""})
    assert "-sS" in cmd
    assert "-sT" not in cmd
    assert "--unprivileged" not in cmd


def test_nmap_custom_scan_honors_an_explicit_connect_scan_choice():
    # Root doesn't override a deliberate operator choice (e.g. being gentle
    # against a fragile target) — only the *default* changed.
    cmd = build_command_for_tool("nmap_custom_scan", {"target": "10.0.0.5", "flags": "-sT"})
    assert "-sT" in cmd
    assert "-sS" not in cmd
    assert "--unprivileged" not in cmd


def test_nmap_custom_scan_full_range_scripted_scan_gets_scaled_timeout():
    cmd = build_command_for_tool(
        "nmap_custom_scan", {"target": "10.0.0.5", "flags": "-sV -sC -p-"}
    )
    assert "--host-timeout 3600s" in cmd


def test_nmap_custom_scan_host_timeout_none_removes_the_cap():
    cmd = build_command_for_tool(
        "nmap_custom_scan", {"target": "10.0.0.5", "flags": "-sV -sC -p-", "host_timeout": "none"}
    )
    assert "--host-timeout" not in cmd


def test_nmap_service_scan_host_timeout_override():
    cmd = build_command_for_tool(
        "nmap_service_scan", {"target": "10.0.0.5", "host_timeout": "20m"}
    )
    assert "--host-timeout 20m" in cmd
