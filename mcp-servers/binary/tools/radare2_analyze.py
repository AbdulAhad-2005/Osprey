"""
Execute Radare2 for binary analysis and reverse engineering with enhanced logging.

Args:
    binary: Path to the binary file
    commands: Radare2 commands to execute
    additional_args: Additional Radare2 arguments

Returns:
    Binary analysis results

Harvested: HexStrike `radare2_analyze` -> `/api/tools/radare2`.
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

TOOL_NAME = "radare2_analyze"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    import os
    import tempfile

    binary = params.get("binary", "")
    commands = params.get("commands", "")
    additional_args = params.get("additional_args", "")
    if commands:
        fd, path = tempfile.mkstemp(suffix=".r2", prefix="r2_cmds_")
        with os.fdopen(fd, "w") as f:
            f.write(commands)
        command = f"r2 -i {path} -q {binary}"
    else:
        command = f"r2 -q {binary}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(binary: str = '', commands: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"binary": binary, "commands": commands, "additional_args": additional_args}
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
