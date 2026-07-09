"""
Execute Foremost for file carving with enhanced logging.

Args:
    input_file: Input file or device to carve
    output_dir: Output directory for carved files
    file_types: File types to carve (jpg,gif,png,etc.)
    additional_args: Additional Foremost arguments

Returns:
    File carving results

Harvested: HexStrike `foremost_carving` -> `/api/tools/foremost`.
Category: forensics
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

TOOL_NAME = "foremost_carving"
CATEGORY = "forensics"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    input_file = params.get("input_file", "")
    output_dir = params.get("output_dir", "/tmp/foremost_output")
    file_types = params.get("file_types", "")
    additional_args = params.get("additional_args", "")
    command = f"foremost -o {output_dir}"
    if file_types:
        command += f" -t {file_types}"
    if additional_args:
        command += f" {additional_args}"
    command += f" {input_file}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(input_file: str = '', output_dir: str = '/tmp/foremost_output', file_types: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"input_file": input_file, "output_dir": output_dir, "file_types": file_types, "additional_args": additional_args}
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
