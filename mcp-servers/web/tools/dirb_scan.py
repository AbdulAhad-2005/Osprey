"""
Execute Dirb for directory brute forcing with enhanced logging.

Args:
    url: The target URL
    wordlist: Path to wordlist file
    additional_args: Additional Dirb arguments

Returns:
    Scan results with enhanced telemetry

Harvested: HexStrike `dirb_scan` -> `/api/tools/dirb`.
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

TOOL_NAME = "dirb_scan"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    url = params.get("url", "")
    wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    additional_args = params.get("additional_args", "")
    command = f"dirb {q(url)} {wordlist}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', wordlist: str = '/usr/share/wordlists/dirb/common.txt', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "wordlist": wordlist, "additional_args": additional_args}
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
