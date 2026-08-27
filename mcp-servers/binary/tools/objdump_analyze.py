"""
Analyze a binary using objdump with enhanced logging.

Args:
    binary: Path to the binary file
    disassemble: Whether to disassemble the binary
    additional_args: Additional objdump arguments

Returns:
    Binary analysis results

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

TOOL_NAME = "objdump_analyze"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    binary = params.get("binary", "")
    disassemble = params.get("disassemble", True)
    additional_args = params.get("additional_args", "")
    command = f"objdump"
    if disassemble:
        command += " -d"
        command += " -x"
    if additional_args:
        command += f" {additional_args}"
    command += f" {binary}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(binary: str = '', disassemble: bool = True, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"binary": binary, "disassemble": disassemble, "additional_args": additional_args}
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
