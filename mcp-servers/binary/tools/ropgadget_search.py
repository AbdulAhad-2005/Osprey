"""
Search for ROP gadgets in a binary using ROPgadget with enhanced logging.

Args:
    binary: Path to the binary file
    gadget_type: Type of gadgets to search for
    additional_args: Additional ROPgadget arguments

Returns:
    ROP gadget search results

Harvested: HexStrike `ropgadget_search` -> `/api/tools/ropgadget`.
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

TOOL_NAME = "ropgadget_search"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    binary = params.get("binary", "")
    gadget_type = params.get("gadget_type", "")
    additional_args = params.get("additional_args", "")
    command = f"ROPgadget --binary {binary}"
    if gadget_type:
        command += f" --only '{gadget_type}'"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(binary: str = '', gadget_type: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"binary": binary, "gadget_type": gadget_type, "additional_args": additional_args}
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
