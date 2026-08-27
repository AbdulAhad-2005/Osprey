"""
Execute rpcclient for RPC enumeration with enhanced logging.

Args:
    target: The target IP address
    username: Username for authentication
    password: Password for authentication
    domain: Domain for authentication
    commands: Semicolon-separated RPC commands
    additional_args: Additional rpcclient arguments

Returns:
    RPC enumeration results

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

TOOL_NAME = "rpcclient_enumeration"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    target = params.get("target", "")
    username = params.get("username", "")
    password = params.get("password", "")
    domain = params.get("domain", "")
    commands = params.get("commands", "enumdomusers;enumdomgroups;querydominfo")
    additional_args = params.get("additional_args", "")
    if username and password:
        auth_string = f"-U {username}%{password}"
    elif username:
        auth_string = f"-U {username}"
    else:
        auth_string = "-U ''"
    if domain:
        auth_string += f" -W {q(domain)}"
    command_sequence = commands.replace(";", "\\n")
    command = f"echo -e '{command_sequence}' | rpcclient {auth_string} {q(target)}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', username: str = '', password: str = '', domain: str = '', commands: str = 'enumdomusers;enumdomgroups;querydominfo', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "username": username, "password": password, "domain": domain, "commands": commands, "additional_args": additional_args}
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
