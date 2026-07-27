"""
Execute anew for appending new lines to files (useful for data processing).

Args:
    input_data: Input data to process
    output_file: Output file path
    additional_args: Additional anew arguments

Returns:
    Data processing results with unique line filtering

Harvested: HexStrike `anew_data_processing` -> `/api/tools/anew`.
Category: recon
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

TOOL_NAME = "anew_data_processing"
CATEGORY = "recon"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    input_data = params.get("input_data", "")
    output_file = params.get("output_file", "")
    additional_args = params.get("additional_args", "")
    if output_file:
        command = f"echo '{input_data}' | anew {output_file}"
    else:
        command = f"echo '{input_data}' | anew"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(input_data: str = '', output_file: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"input_data": input_data, "output_file": output_file, "additional_args": additional_args}
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
