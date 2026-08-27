"""
Execute ExifTool for metadata extraction with enhanced logging.

Args:
    file_path: Path to file for metadata extraction
    output_format: Output format (json, xml, csv)
    tags: Specific tags to extract
    additional_args: Additional ExifTool arguments

Returns:
    Metadata extraction results

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

TOOL_NAME = "exiftool_extract"
CATEGORY = "forensics"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    file_path = params.get("file_path", "")
    output_format = params.get("output_format", "")  # json, xml, csv
    tags = params.get("tags", "")
    additional_args = params.get("additional_args", "")
    command = f"exiftool"
    if output_format:
        command += f" -{output_format}"
    if tags:
        command += f" -{tags}"
    if additional_args:
        command += f" {additional_args}"
    command += f" {file_path}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(file_path: str = '', output_format: str = '', tags: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"file_path": file_path, "output_format": output_format, "tags": tags, "additional_args": additional_args}
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
