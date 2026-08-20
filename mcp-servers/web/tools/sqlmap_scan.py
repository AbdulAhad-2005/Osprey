"""
Execute SQLMap for SQL injection testing with enhanced logging.

Args:
    url: The target URL
    data: POST data for testing
    additional_args: Additional SQLMap arguments

Returns:
    SQL injection test results

Harvested: HexStrike `sqlmap_scan` -> `/api/tools/sqlmap`.
Category: web
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.command_utils import q
from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "sqlmap_scan"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    url = params.get("url", "")
    data = params.get("data", "")
    additional_args = params.get("additional_args", "")
    command = f"sqlmap -u {q(url)} --batch"
    if data:
        command += f" --data={q(data)}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', data: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "data": data, "additional_args": additional_args}
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
