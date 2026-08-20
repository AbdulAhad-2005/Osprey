"""
Execute arp-scan for network discovery with enhanced logging.

Args:
    target: The target IP range (if not using local_network)
    interface: Network interface to use
    local_network: Scan local network
    timeout: Timeout in milliseconds
    retry: Number of retries
    additional_args: Additional arp-scan arguments

Returns:
    Network discovery results via ARP scanning

Harvested: HexStrike `arp_scan_discovery` -> `/api/tools/arp-scan`.
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
from _core.command_utils import q

TOOL_NAME = "arp_scan_discovery"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    interface = params.get("interface", "")
    local_network = params.get("local_network", False)
    timeout = params.get("timeout", 500)
    retry = params.get("retry", 3)
    additional_args = params.get("additional_args", "")
    command = f"arp-scan -t {timeout} -r {retry}"
    if interface:
        command += f" -I {interface}"
    if local_network:
        command += " -l"
    elif target:
        command += f" {q(target)}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', interface: str = '', local_network: bool = False, timeout: int = 500, retry: int = 3, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "interface": interface, "local_network": local_network, "timeout": timeout, "retry": retry, "additional_args": additional_args}
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
