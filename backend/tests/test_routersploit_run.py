"""routersploit_run wrapper: command construction, input sanitization, and
output parsing. (Live execution needs rsf installed + an authorized target —
see docs/network-device-benchmark.md for the confirmation runbook.)"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MCP_SERVERS = ROOT / "mcp-servers"


def _load():
    if str(MCP_SERVERS) not in sys.path:
        sys.path.insert(0, str(MCP_SERVERS))
    spec = importlib.util.spec_from_file_location(
        "_test_routersploit_run", MCP_SERVERS / "exploit" / "tools" / "routersploit_run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rsf = _load()


def test_build_command_default_autopwn():
    cmd = rsf.build_command(module="scanners/autopwn", target="192.0.2.10", port="80")
    assert "use scanners/autopwn" in cmd
    assert "set target 192.0.2.10" in cmd
    assert "set port 80" in cmd
    assert "run" in cmd
    assert "command -v rsf.py" in cmd  # runtime binary discovery


def test_build_command_requires_target():
    with pytest.raises(ValueError):
        rsf.build_command(module="scanners/autopwn", target="")


def test_build_command_rejects_bad_module():
    with pytest.raises(ValueError):
        rsf.build_command(module="scanners/../../etc/passwd; rm -rf /", target="192.0.2.10")


def test_build_command_sanitizes_injection_in_target():
    # A newline in target must not become a standalone rsf command line — it is
    # collapsed to a space so the whole thing stays the target VALUE.
    cmd = rsf.build_command(module="scanners/autopwn", target="192.0.2.10\nset payload evil")
    assert "192.0.2.10 set payload evil" in cmd   # folded onto the target line
    assert "\nset payload evil" not in cmd        # not a new command line


def test_build_command_passes_extra_options():
    cmd = rsf.build_command(module="creds/routers/mikrotik/ssh_default_creds",
                            target="192.0.2.10", options={"threads": 4})
    assert "set threads 4" in cmd


class _R:
    def __init__(self, raw):
        self.raw_stdout = raw


def test_parse_detects_vulnerable():
    out = rsf.parse(_R(
        "[*] Running module scanners/autopwn...\n"
        "[+] 192.0.2.10 Target is vulnerable to exploits/routers/dlink/dir_300_600_rce\n"
        "[*] Starting vulnerability check...\n"
    ))
    assert out["vulnerable"] is True
    assert any("vulnerable" in s.lower() for s in out["status_lines"])


def test_parse_detects_not_vulnerable():
    out = rsf.parse(_R("[*] Running...\n[-] Target is not vulnerable\n"))
    assert out["vulnerable"] is False


def test_parse_extracts_credentials():
    out = rsf.parse(_R(
        "[*] Running creds module...\n"
        "[+] Credentials found!\n"
        "   Login   Password\n"
        "   admin   admin\n"
    ))
    assert any("credentials found" in c.lower() for c in out["credentials"])


def test_registered_as_gated_exploit():
    from osprey.services.tool_registry import get_tool_definition

    td = get_tool_definition("routersploit_run")
    assert td is not None
    assert td.category.value == "exploit"
    assert td.safety_level.value == "gated"  # never engine-auto-run; needs authorization
