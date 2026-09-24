from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP_SERVERS = ROOT / "mcp-servers"


def _load_tool(category: str, name: str):
    if str(MCP_SERVERS) not in sys.path:
        sys.path.insert(0, str(MCP_SERVERS))
    module_path = MCP_SERVERS / category / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_test_tool_{category}_{name}", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_httpx_probe_discovers_projectdiscovery_binary_at_runtime() -> None:
    httpx_probe = _load_tool("recon", "httpx_probe")

    command = httpx_probe.build_command(target="https://example.com", tech_detect=True)

    assert "httpx-toolkit httpx-pd httpx" in command
    assert '"$HTTPX_BIN" -u https://example.com' in command
    assert "-tech-detect" in command


def test_dirsearch_scan_uses_configured_wordlist_or_runtime_default() -> None:
    dirsearch_scan = _load_tool("web", "dirsearch_scan")

    command = dirsearch_scan.build_command(
        url="https://example.com",
        extensions="php,txt",
        wordlist="/missing/common.txt",
        threads=5,
    )

    assert "WORDLIST=/missing/common.txt" in command
    assert "WORDLIST_ARGS=()" in command
    assert 'if [ ! -f "$WORDLIST" ]; then' in command
    assert 'WORDLIST_ARGS=(-w "$WORDLIST")' in command
    assert 'dirsearch -u https://example.com -e php,txt "${WORDLIST_ARGS[@]}" -t 5' in command
    assert "/usr/share/seclists" not in command


def test_naabu_port_scan_preserves_native_range_syntax() -> None:
    naabu_port_scan = _load_tool("network", "naabu_port_scan")

    command = naabu_port_scan.build_command(target="1.2.3.4", ports="1-3,443")

    assert "-p 1-3,443" in command


def test_naabu_port_scan_preserves_full_range_capability() -> None:
    naabu_port_scan = _load_tool("network", "naabu_port_scan")

    command = naabu_port_scan.build_command(target="1.2.3.4", ports="1-10000")
    assert "-p 1-10000" in command


def test_origin_ip_attribution_uses_stable_section_markers() -> None:
    origin_ip_attribution = _load_tool("recon", "origin_ip_attribution")

    command = origin_ip_attribution.build_command(domain="example.com")

    assert "printf '%s\\n' '=== Resolving example.com ==='" in command
    assert 'echo "=== Resolving "' not in command
    assert "curl -sI --max-time 30 https://example.com" in command
