"""
Execute Amass for subdomain enumeration with enhanced logging.

Args:
    domain: The target domain
    mode: Amass mode (enum, intel, viz)
    additional_args: Additional Amass arguments

Returns:
    Subdomain enumeration results

Harvested: HexStrike `amass_scan` -> `/api/tools/amass`.
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

TOOL_NAME = "amass_scan"
CATEGORY = "recon"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    domain = params.get("domain", "")
    mode = str(params.get("mode", "enum")).strip().lower()
    additional_args = params.get("additional_args", "")

    # Kali's /usr/bin/amass wrapper may invoke sudo for libpostal setup — call binary directly.
    # passive is a sub-mode of enum, not a top-level amass subcommand.
    if mode == "passive":
        command = f"/usr/lib/amass/amass enum -passive -d {domain}"
    elif mode == "intel":
        command = f"/usr/lib/amass/amass intel -d {domain}"
    else:
        command = f"/usr/lib/amass/amass enum -d {domain}"

    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(domain: str = '', mode: str = 'enum', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"domain": domain, "mode": mode, "additional_args": additional_args}
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
