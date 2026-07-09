"""
Execute Masscan for high-speed Internet-scale port scanning with intelligent rate limiting.

Args:
    target: The target IP address or CIDR range
    ports: Port range to scan
    rate: Packets per second rate
    interface: Network interface to use
    router_mac: Router MAC address
    source_ip: Source IP address
    banners: Enable banner grabbing
    additional_args: Additional Masscan arguments

Returns:
    High-speed port scanning results with intelligent rate limiting

Harvested: HexStrike `masscan_high_speed` -> `/api/tools/masscan`.
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

TOOL_NAME = "masscan_high_speed"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    ports = params.get("ports", "1-65535")
    rate = params.get("rate", 1000)
    interface = params.get("interface", "")
    router_mac = params.get("router_mac", "")
    source_ip = params.get("source_ip", "")
    banners = params.get("banners", False)
    additional_args = params.get("additional_args", "")
    command = f"masscan {target} -p{ports} --rate={rate}"
    if interface:
        command += f" -e {interface}"
    if router_mac:
        command += f" --router-mac {router_mac}"
    if source_ip:
        command += f" --source-ip {source_ip}"
    if banners:
        command += " --banners"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', ports: str = '1-65535', rate: int = 1000, interface: str = '', router_mac: str = '', source_ip: str = '', banners: bool = False, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "ports": ports, "rate": rate, "interface": interface, "router_mac": router_mac, "source_ip": source_ip, "banners": banners, "additional_args": additional_args}
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
