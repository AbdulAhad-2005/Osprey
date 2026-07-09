"""
Execute Enum4linux for SMB enumeration with enhanced logging.

Args:
    target: The target IP address
    additional_args: Additional Enum4linux arguments

Returns:
    SMB enumeration results

Harvested: HexStrike `enum4linux_scan` -> `/api/tools/enum4linux`.
Category: network
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

TOOL_NAME = "enum4linux_scan"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    additional_args = params.get("additional_args", "-a")
    command = f"enum4linux {additional_args} {target}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', additional_args: str = '-a', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "additional_args": additional_args}
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
