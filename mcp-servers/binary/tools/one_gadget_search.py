"""
Execute one_gadget to find one-shot RCE gadgets in libc.

Args:
    libc_path: Path to libc binary
    level: Constraint level (0, 1, 2)
    additional_args: Additional one_gadget arguments

Returns:
    One-shot RCE gadget search results

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

TOOL_NAME = "one_gadget_search"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    libc_path = params.get("libc_path", "")
    level = params.get("level", 1)  # 0, 1, 2 for different constraint levels
    additional_args = params.get("additional_args", "")
    command = f"one_gadget {libc_path} --level {level}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(libc_path: str = '', level: int = 1, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"libc_path": libc_path, "level": level, "additional_args": additional_args}
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
