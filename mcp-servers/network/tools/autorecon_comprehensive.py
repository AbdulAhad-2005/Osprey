"""
Execute AutoRecon for comprehensive automated reconnaissance.

Args:
    target: The target IP address or hostname
    output_dir: Output directory for results
    port_scans: Port scan configuration
    service_scans: Service scan configuration
    heartbeat: Heartbeat interval in seconds
    timeout: Timeout for individual scans
    additional_args: Additional AutoRecon arguments

Returns:
    Comprehensive automated reconnaissance results

Harvested: HexStrike `autorecon_comprehensive` -> `/api/tools/autorecon`.
Category: network
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult
from _autorecon_results import parse as _collect_dir_results

TOOL_NAME = "autorecon_comprehensive"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    output_dir = params.get("output_dir", "/tmp/autorecon")
    port_scans = params.get("port_scans", "top-100-ports")
    service_scans = params.get("service_scans", "default")
    heartbeat = params.get("heartbeat", 60)
    timeout = params.get("timeout", 300)
    additional_args = params.get("additional_args", "")
    command = f"autorecon {target} -o {output_dir} --heartbeat {heartbeat} --timeout {timeout}"
    if port_scans != "default":
        command += f" --port-scans {port_scans}"
    if service_scans != "default":
        command += f" --service-scans {service_scans}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    # AutoRecon writes findings to output_dir, not stdout — fold them back in.
    return _collect_dir_results(result)

def run(target: str = '', output_dir: str = '/tmp/autorecon', port_scans: str = 'top-100-ports', service_scans: str = 'default', heartbeat: int = 60, timeout: int = 300, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "output_dir": output_dir, "port_scans": port_scans, "service_scans": service_scans, "heartbeat": heartbeat, "timeout": timeout, "additional_args": additional_args}
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
