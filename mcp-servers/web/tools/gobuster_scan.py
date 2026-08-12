"""
Execute Gobuster to find directories, DNS subdomains, or virtual hosts with enhanced logging.

Args:
    url: The target URL
    mode: Scan mode (dir, dns, fuzz, vhost)
    wordlist: Path to wordlist file
    additional_args: Additional Gobuster arguments

Returns:
    Scan results with enhanced telemetry

Harvested: HexStrike `gobuster_scan` -> `/api/tools/gobuster`.
Category: web
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "gobuster_scan"
CATEGORY = "web"

# Bundled wordlist (Kali image ships none); mcp-servers is mounted at this path.
from _core.paths import container_or_local

_DEFAULT_WORDLIST = container_or_local(
    "/home/mcpuser/mcp-servers/recon/tools/_wordlists/common-web.txt",
    str(Path(__file__).resolve().parents[2] / "recon" / "tools" / "_wordlists" / "common-web.txt"),
)


def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    url = str(params.get("url") or params.get("target") or "").strip()
    mode = str(params.get("mode") or "dir").strip()
    wordlist = params.get("wordlist") or _DEFAULT_WORDLIST
    additional_args = str(params.get("additional_args") or "").strip()
    if not url:
        raise ValueError("gobuster_scan requires url=")
    # dns mode uses -d (domain) not -u; dir/vhost use -u and can skip TLS verify.
    if mode == "dns":
        command = f"gobuster dns -d {url} -w {wordlist}"
    else:
        command = f"gobuster {mode} -u {url} -w {wordlist} -k"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', mode: str = 'dir', wordlist: str = '/usr/share/wordlists/dirb/common.txt', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "mode": mode, "wordlist": wordlist, "additional_args": additional_args}
    command = build_command(**params)
    return run_tool(
        TOOL_NAME,
        command,
        params=params,
        timeout=exec_timeout,
        use_cache=use_cache,
        use_recovery=use_recovery,
        parse_fn=parse,
    )
