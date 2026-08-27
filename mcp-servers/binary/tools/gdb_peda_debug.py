"""
Execute GDB with PEDA for enhanced debugging and exploitation.

Args:
    binary: Binary to debug
    commands: GDB commands to execute
    attach_pid: Process ID to attach to
    core_file: Core dump file to analyze
    additional_args: Additional GDB arguments

Returns:
    Enhanced debugging results with PEDA

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

TOOL_NAME = "gdb_peda_debug"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    import os
    import tempfile

    binary = params.get("binary", "")
    commands = params.get("commands", "")
    attach_pid = params.get("attach_pid", 0)
    core_file = params.get("core_file", "")
    additional_args = params.get("additional_args", "")
    command = "gdb -q"
    if binary:
        command += f" {binary}"
    if core_file:
        command += f" {core_file}"
    if attach_pid:
        command += f" -p {attach_pid}"
    if commands:
        fd, path = tempfile.mkstemp(suffix=".gdb", prefix="gdb_peda_")
        with os.fdopen(fd, "w") as f:
            f.write("source ~/peda/peda.py\n")
            f.write(commands)
            f.write("\nquit\n")
        command += f" -x {path}"
    else:
        command += " -ex 'source ~/peda/peda.py' -ex 'quit'"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(binary: str = '', commands: str = '', attach_pid: int = 0, core_file: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"binary": binary, "commands": commands, "attach_pid": attach_pid, "core_file": core_file, "additional_args": additional_args}
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
