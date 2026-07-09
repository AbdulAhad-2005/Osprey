"""
Execute qsreplace for query string parameter replacement.

Args:
    urls: URLs to process
    replacement: Replacement string for parameters
    additional_args: Additional qsreplace arguments

Returns:
    Parameter replacement results for fuzzing

Harvested: HexStrike `qsreplace_parameter_replacement` -> `/api/tools/qsreplace`.
Category: web
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

TOOL_NAME = "qsreplace_parameter_replacement"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    urls = params.get("urls", "")
    replacement = params.get("replacement", "FUZZ")
    additional_args = params.get("additional_args", "")
    command = f"echo '{urls}' | qsreplace '{replacement}'"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(urls: str = '', replacement: str = 'FUZZ', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"urls": urls, "replacement": replacement, "additional_args": additional_args}
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
