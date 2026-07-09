"""
Execute pwninit for CTF binary exploitation setup.

Args:
    binary: Binary file to set up
    libc: Libc file to use
    ld: Loader file to use
    template_type: Template type (python, c)
    additional_args: Additional pwninit arguments

Returns:
    CTF binary exploitation setup results

Harvested: HexStrike `pwninit_setup` -> `/api/tools/pwninit`.
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

TOOL_NAME = "pwninit_setup"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    binary = params.get("binary", "")
    libc = params.get("libc", "")
    ld = params.get("ld", "")
    template_type = params.get("template_type", "python")  # python, c
    additional_args = params.get("additional_args", "")
    command = f"pwninit --bin {binary}"
    if libc:
        command += f" --libc {libc}"
    if ld:
        command += f" --ld {ld}"
    if template_type:
        command += f" --template {template_type}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(binary: str = '', libc: str = '', ld: str = '', template_type: str = 'python', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"binary": binary, "libc": libc, "ld": ld, "template_type": template_type, "additional_args": additional_args}
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
