"""
Execute dnsenum for DNS enumeration with enhanced logging.

Args:
    domain: Target domain
    dns_server: DNS server to use
    wordlist: Wordlist for brute forcing
    additional_args: Additional dnsenum arguments

Returns:
    DNS enumeration results

Harvested: HexStrike `dnsenum_scan` -> `/api/tools/dnsenum`.
Category: recon
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

TOOL_NAME = "dnsenum_scan"
CATEGORY = "recon"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    domain = params.get("domain", "")
    dns_server = params.get("dns_server", "")
    wordlist = params.get("wordlist", "")
    additional_args = params.get("additional_args", "")
    command = f"dnsenum {domain}"
    if dns_server:
        command += f" --dnsserver {dns_server}"
    if wordlist:
        command += f" --file {wordlist}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(domain: str = '', dns_server: str = '', wordlist: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"domain": domain, "dns_server": dns_server, "wordlist": wordlist, "additional_args": additional_args}
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
