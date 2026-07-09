"""
Execute x8 for hidden parameter discovery with enhanced logging.

Args:
    url: The target URL
    wordlist: Parameter wordlist
    method: HTTP method
    body: Request body
    headers: Custom headers
    additional_args: Additional x8 arguments

Returns:
    Hidden parameter discovery results

Harvested: HexStrike `x8_parameter_discovery` -> `/api/tools/x8`.
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

TOOL_NAME = "x8_parameter_discovery"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    url = params.get("url", "")
    wordlist = params.get("wordlist", "/usr/share/wordlists/x8/params.txt")
    method = params.get("method", "GET")
    body = params.get("body", "")
    headers = params.get("headers", "")
    additional_args = params.get("additional_args", "")
    command = f"x8 -u {url} -w {wordlist} -X {method}"
    if body:
        command += f" -b '{body}'"
    if headers:
        command += f" -H '{headers}'"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', wordlist: str = '/usr/share/wordlists/x8/params.txt', method: str = 'GET', body: str = '', headers: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "wordlist": wordlist, "method": method, "body": body, "headers": headers, "additional_args": additional_args}
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
