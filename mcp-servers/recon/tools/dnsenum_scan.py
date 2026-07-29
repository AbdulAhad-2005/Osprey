"""
Execute dnsenum for DNS enumeration with enhanced logging.

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
    """Build CLI command — dnsenum requires --enum to perform enumeration."""
    domain = params.get("domain", "")
    dns_server = params.get("dns_server", "")
    wordlist = params.get("wordlist", "")
    additional_args = str(params.get("additional_args", "") or "").strip()

    # dnsenum brute-forces its bundled ~1000-entry wordlist against the target,
    # which routinely runs past the exec timeout on a real domain. Perl block-
    # buffers stdout once it's a pipe (not a tty) rather than line-buffering —
    # without stdbuf, a killed-on-timeout run can leave the OS pipe buffer
    # empty even though dnsenum found records, so the platform's partial-
    # output-on-timeout recovery (mcp_client.py's _drain_partial) has nothing
    # to read. stdbuf forces line buffering so partial results are actually
    # flushed into the pipe as they're found.
    parts = ["stdbuf", "-oL", "-eL", "dnsenum", "--enum", domain]
    if dns_server:
        parts.extend(["--dnsserver", dns_server])
    if wordlist:
        parts.extend(["--file", wordlist])
    if additional_args:
        parts.append(additional_args)
    return " ".join(part for part in parts if part)


def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)


def run(
    domain: str = "",
    dns_server: str = "",
    wordlist: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "domain": domain,
        "dns_server": dns_server,
        "wordlist": wordlist,
        "additional_args": additional_args,
    }
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
