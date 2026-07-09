"""
Execute FFuf for web fuzzing with enhanced logging.

Args:
    url: The target URL
    wordlist: Wordlist file to use
    mode: Fuzzing mode (directory, vhost, parameter)
    match_codes: HTTP status codes to match
    additional_args: Additional FFuf arguments

Returns:
    Web fuzzing results

Harvested: HexStrike `ffuf_scan` -> `/api/tools/ffuf`.
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

TOOL_NAME = "ffuf_scan"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    url = params.get("url", "")
    wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    mode = params.get("mode", "directory")
    match_codes = params.get("match_codes", "200,204,301,302,307,401,403")
    additional_args = params.get("additional_args", "")
    command = f"ffuf"
    if mode == "directory":
        command += f" -u {url}/FUZZ -w {wordlist}"
        command += f" -u {url} -H 'Host: FUZZ' -w {wordlist}"
        command += f" -u {url}?FUZZ=value -w {wordlist}"
        command += f" -u {url} -w {wordlist}"
    command += f" -mc {match_codes}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', wordlist: str = '/usr/share/wordlists/dirb/common.txt', mode: str = 'directory', match_codes: str = '200,204,301,302,307,401,403', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "wordlist": wordlist, "mode": mode, "match_codes": match_codes, "additional_args": additional_args}
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
