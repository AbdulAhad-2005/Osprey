"""
Create a hex dump of a file using xxd with enhanced logging.

Args:
    file_path: Path to the file
    offset: Offset to start reading from
    length: Number of bytes to read
    additional_args: Additional xxd arguments

Returns:
    Hex dump results

Harvested: HexStrike `xxd_hexdump` -> `/api/tools/xxd`.
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

TOOL_NAME = "xxd_hexdump"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    file_path = params.get("file_path", "")
    offset = params.get("offset", "0")
    length = params.get("length", "")
    additional_args = params.get("additional_args", "")
    command = f"xxd -s {offset}"
    if length:
        command += f" -l {length}"
    if additional_args:
        command += f" {additional_args}"
    command += f" {file_path}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(file_path: str = '', offset: str = '0', length: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"file_path": file_path, "offset": offset, "length": length, "additional_args": additional_args}
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
