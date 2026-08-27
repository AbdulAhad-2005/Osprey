"""
Execute DotDotPwn for directory traversal testing with enhanced logging.

Args:
    target: The target hostname or IP
    module: Module to use (http, ftp, tftp, etc.)
    additional_args: Additional DotDotPwn arguments

Returns:
    Directory traversal test results

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
from _core.command_utils import q

TOOL_NAME = "dotdotpwn_scan"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    target = params.get("target", "")
    module = params.get("module", "http")
    additional_args = params.get("additional_args", "")
    command = f"dotdotpwn -m {module} -h {q(target)}"
    if additional_args:
        command += f" {additional_args}"
    command += " -b"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', module: str = 'http', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "module": module, "additional_args": additional_args}
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
