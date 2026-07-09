"""
Execute GDB for binary analysis and debugging with enhanced logging.

Args:
    binary: Path to the binary file
    commands: GDB commands to execute
    script_file: Path to GDB script file
    additional_args: Additional GDB arguments

Returns:
    Binary analysis results

Harvested: HexStrike `gdb_analyze` -> `/api/tools/gdb`.
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

TOOL_NAME = "gdb_analyze"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    import os
    import tempfile

    binary = params.get("binary", "")
    commands = params.get("commands", "")
    script_file = params.get("script_file", "")
    additional_args = params.get("additional_args", "")
    command = f"gdb {binary}"
    if script_file:
        command += f" -x {script_file}"
    if commands:
        fd, path = tempfile.mkstemp(suffix=".gdb", prefix="gdb_cmds_")
        with os.fdopen(fd, "w") as f:
            f.write(commands)
        command += f" -x {path}"
    if additional_args:
        command += f" {additional_args}"
    command += " -batch"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(binary: str = '', commands: str = '', script_file: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"binary": binary, "commands": commands, "script_file": script_file, "additional_args": additional_args}
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
