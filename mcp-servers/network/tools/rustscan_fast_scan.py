"""
Execute Rustscan for ultra-fast port scanning with enhanced logging.

Args:
    target: The target IP address or hostname
    ports: Specific ports to scan (e.g., "22,80,443")
    ulimit: File descriptor limit
    batch_size: Batch size for scanning
    timeout: Timeout in milliseconds
    scripts: Run Nmap scripts on discovered ports
    additional_args: Additional Rustscan arguments

Returns:
    Ultra-fast port scanning results

Harvested: HexStrike `rustscan_fast_scan` -> `/api/tools/rustscan`.
Category: network
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "rustscan_fast_scan"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    ports = params.get("ports", "")
    # Gentler defaults: the harvested 4500-batch / 5000-ulimit floods shared
    # hosts and gets the scanning source IP-banned mid-engagement. 1000/2000 is
    # still fast but survives rate-limited / shared-hosting targets. Override via
    # batch_size= / ulimit= when the target can take it.
    ulimit = params.get("ulimit", 2000)
    batch_size = params.get("batch_size", 1000)
    timeout = params.get("timeout", 2000)
    scripts = params.get("scripts", "")
    additional_args = params.get("additional_args", "")
    command = f"rustscan -a {shlex.quote(str(target))} --ulimit {shlex.quote(str(ulimit))} -b {shlex.quote(str(batch_size))} -t {shlex.quote(str(timeout))}"
    if ports:
        command += f" -p {shlex.quote(str(ports))}"
    if scripts:
        command += f" -- -sC -sV"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', ports: str = '', ulimit: int = 2000, batch_size: int = 1000, timeout: int = 2000, scripts: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "ports": ports, "ulimit": ulimit, "batch_size": batch_size, "timeout": timeout, "scripts": scripts, "additional_args": additional_args}
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
