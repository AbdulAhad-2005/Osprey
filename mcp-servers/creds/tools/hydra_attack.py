"""
Execute Hydra for password brute forcing with enhanced logging.

Args:
    target: The target IP or hostname
    service: The service to attack (ssh, ftp, http, etc.)
    username: Single username to test
    username_file: File containing usernames
    password: Single password to test
    password_file: File containing passwords
    additional_args: Additional Hydra arguments

Returns:
    Brute force attack results

Harvested: HexStrike `hydra_attack` -> `/api/tools/hydra`.
Category: creds
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

TOOL_NAME = "hydra_attack"
CATEGORY = "creds"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    service = params.get("service", "")
    username = params.get("username", "")
    username_file = params.get("username_file", "")
    password = params.get("password", "")
    password_file = params.get("password_file", "")
    additional_args = params.get("additional_args", "")
    command = f"hydra -t 4"
    if username:
        command += f" -l {q(username)}"
        command += f" -L {q(username_file)}"
    if password:
        command += f" -p {q(password)}"
        command += f" -P {q(password_file)}"
    if additional_args:
        command += f" {additional_args}"
    command += f" {q(target)} {q(service)}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', service: str = '', username: str = '', username_file: str = '', password: str = '', password_file: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "service": service, "username": username, "username_file": username_file, "password": password, "password_file": password_file, "additional_args": additional_args}
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
