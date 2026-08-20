"""
Execute Arjun for parameter discovery with enhanced logging.

Args:
    url: Target URL
    method: HTTP method (GET, POST, etc.)
    data: POST data for testing
    headers: Custom headers
    timeout: Request timeout
    output_file: Output file path
    additional_args: Additional Arjun arguments

Returns:
    Parameter discovery results

Harvested: HexStrike `arjun_scan` -> `/api/tools/arjun`.
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

TOOL_NAME = "arjun_scan"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    url = params.get("url", "")
    method = params.get("method", "GET")
    wordlist = params.get("wordlist", "")
    delay = params.get("delay", 0)
    threads = params.get("threads", 25)
    stable = params.get("stable", False)
    additional_args = params.get("additional_args", "")
    command = f"arjun -u {q(url)} -m {method} -t {threads}"
    if wordlist:
        command += f" -w {wordlist}"
    if delay > 0:
        command += f" -d {delay}"
    if stable:
        command += " --stable"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', method: str = 'GET', wordlist: str = '', delay: int = 0, threads: int = 25, stable: bool = False, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "method": method, "wordlist": wordlist, "delay": delay, "threads": threads, "stable": stable, "additional_args": additional_args}
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
