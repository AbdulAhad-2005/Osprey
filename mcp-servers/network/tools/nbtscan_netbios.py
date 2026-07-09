"""
Execute nbtscan for NetBIOS name scanning with enhanced logging.

Args:
    target: The target IP address or range
    verbose: Enable verbose output
    timeout: Timeout in seconds
    additional_args: Additional nbtscan arguments

Returns:
    NetBIOS name scanning results

Harvested: HexStrike `nbtscan_netbios` -> `/api/tools/nbtscan`.
Category: network
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

TOOL_NAME = "nbtscan_netbios"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    verbose = params.get("verbose", False)
    timeout = params.get("timeout", 2)
    additional_args = params.get("additional_args", "")
    command = f"nbtscan -t {timeout}"
    if verbose:
        command += " -v"
    command += f" {target}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', verbose: bool = False, timeout: int = 2, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "verbose": verbose, "timeout": timeout, "additional_args": additional_args}
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
