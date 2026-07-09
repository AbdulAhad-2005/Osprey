"""
Execute NetExec (formerly CrackMapExec) for network enumeration with enhanced logging.

Args:
    target: The target IP or network
    protocol: Protocol to use (smb, ssh, winrm, etc.)
    username: Username for authentication
    password: Password for authentication
    hash_value: Hash for pass-the-hash attacks
    module: NetExec module to execute
    additional_args: Additional NetExec arguments

Returns:
    Network enumeration results

Harvested: HexStrike `netexec_scan` -> `/api/tools/netexec`.
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

TOOL_NAME = "netexec_scan"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    protocol = params.get("protocol", "smb")
    username = params.get("username", "")
    password = params.get("password", "")
    hash_value = params.get("hash", "")
    module = params.get("module", "")
    additional_args = params.get("additional_args", "")
    command = f"nxc {protocol} {target}"
    if username:
        command += f" -u {username}"
    if password:
        command += f" -p {password}"
    if hash_value:
        command += f" -H {hash_value}"
    if module:
        command += f" -M {module}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', protocol: str = 'smb', username: str = '', password: str = '', hash: str = '', module: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "protocol": protocol, "username": username, "password": password, "hash": hash, "module": module, "additional_args": additional_args}
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
