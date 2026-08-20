"""
Execute Enum4linux-ng for advanced SMB enumeration with enhanced logging.

Args:
    target: The target IP address
    username: Username for authentication
    password: Password for authentication
    domain: Domain for authentication
    shares: Enumerate shares
    users: Enumerate users
    groups: Enumerate groups
    policy: Enumerate policies
    additional_args: Additional Enum4linux-ng arguments

Returns:
    Advanced SMB enumeration results

Harvested: HexStrike `enum4linux_ng_advanced` -> `/api/tools/enum4linux-ng`.
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

TOOL_NAME = "enum4linux_ng_advanced"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    username = params.get("username", "")
    password = params.get("password", "")
    domain = params.get("domain", "")
    shares = params.get("shares", True)
    users = params.get("users", True)
    groups = params.get("groups", True)
    policy = params.get("policy", True)
    additional_args = params.get("additional_args", "")
    command = f"enum4linux-ng {q(target)}"
    if username:
        command += f" -u {username}"
    if password:
        command += f" -p {password}"
    if domain:
        command += f" -d {q(domain)}"
    # enum4linux-ng has no "-A <list>" syntax — -A is a standalone "do all
    # simple enumeration" flag; individual categories are separate real
    # flags (-S/-U/-G/-P). Emit -A only when all four are requested.
    enum_flags = []
    if shares:
        enum_flags.append("-S")
    if users:
        enum_flags.append("-U")
    if groups:
        enum_flags.append("-G")
    if policy:
        enum_flags.append("-P")
    if len(enum_flags) == 4:
        command += " -A"
    elif enum_flags:
        command += " " + " ".join(enum_flags)
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', username: str = '', password: str = '', domain: str = '', shares: bool = True, users: bool = True, groups: bool = True, policy: bool = True, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "username": username, "password": password, "domain": domain, "shares": shares, "users": users, "groups": groups, "policy": policy, "additional_args": additional_args}
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
