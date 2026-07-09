"""
Execute ropper for advanced ROP/JOP gadget searching.

Args:
    binary: Binary to search for gadgets
    gadget_type: Type of gadgets (rop, jop, sys, all)
    quality: Gadget quality level (1-5)
    arch: Target architecture (x86, x86_64, arm, etc.)
    search_string: Specific gadget pattern to search for
    additional_args: Additional ropper arguments

Returns:
    Advanced ROP/JOP gadget search results

Harvested: HexStrike `ropper_gadget_search` -> `/api/tools/ropper`.
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

TOOL_NAME = "ropper_gadget_search"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    binary = params.get("binary", "")
    gadget_type = params.get("gadget_type", "rop")  # rop, jop, sys, all
    quality = params.get("quality", 1)  # 1-5, higher = better quality
    arch = params.get("arch", "")  # x86, x86_64, arm, etc.
    search_string = params.get("search_string", "")
    additional_args = params.get("additional_args", "")
    command = f"ropper --file {binary}"
    if gadget_type == "rop":
        command += " --rop"
        command += " --jop"
        command += " --sys"
        command += " --all"
    if quality > 1:
        command += f" --quality {quality}"
    if arch:
        command += f" --arch {arch}"
    if search_string:
        command += f" --search '{search_string}'"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(binary: str = '', gadget_type: str = 'rop', quality: int = 1, arch: str = '', search_string: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"binary": binary, "gadget_type": gadget_type, "quality": quality, "arch": arch, "search_string": search_string, "additional_args": additional_args}
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
