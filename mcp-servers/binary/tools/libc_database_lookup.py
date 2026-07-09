"""
Execute libc-database for libc identification and offset lookup.

Args:
    action: Action to perform (find, dump, download)
    symbols: Symbols with offsets for find action (format: "symbol1:offset1 symbol2:offset2")
    libc_id: Libc ID for dump/download actions
    additional_args: Additional arguments

Returns:
    Libc database lookup results

Harvested: HexStrike `libc_database_lookup` -> `/api/tools/libc-database`.
Category: binary
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

TOOL_NAME = "libc_database_lookup"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    action = params.get("action", "find")
    symbols = params.get("symbols", "")
    libc_id = params.get("libc_id", "")
    additional_args = params.get("additional_args", "")
    base_command = (
        "cd /opt/libc-database 2>/dev/null || "
        "cd ~/libc-database 2>/dev/null || "
        "echo 'libc-database not found'"
    )
    if action == "find":
        command = f"{base_command} && ./find {symbols}"
    elif action == "dump":
        command = f"{base_command} && ./dump {libc_id}"
    elif action == "download":
        command = f"{base_command} && ./download {libc_id}"
    else:
        raise ValueError(f"Invalid libc-database action: {action}")
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(action: str = 'find', symbols: str = '', libc_id: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"action": action, "symbols": symbols, "libc_id": libc_id, "additional_args": additional_args}
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
