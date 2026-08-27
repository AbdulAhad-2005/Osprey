"""
Execute Volatility for memory forensics analysis with enhanced logging.

Args:
    memory_file: Path to memory dump file
    plugin: Volatility plugin to use
    profile: Memory profile to use
    additional_args: Additional Volatility arguments

Returns:
    Memory forensics analysis results

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

TOOL_NAME = "volatility_analyze"
CATEGORY = "forensics"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    memory_file = params.get("memory_file", "")
    plugin = params.get("plugin", "")
    profile = params.get("profile", "")
    additional_args = params.get("additional_args", "")
    command = f"volatility -f {memory_file}"
    if profile:
        command += f" --profile={profile}"
    command += f" {plugin}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(memory_file: str = '', plugin: str = '', profile: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"memory_file": memory_file, "plugin": plugin, "profile": profile, "additional_args": additional_args}
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
