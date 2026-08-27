"""
Execute uro for filtering out similar URLs.

Args:
    urls: URLs to filter
    whitelist: Whitelist patterns
    blacklist: Blacklist patterns
    additional_args: Additional uro arguments

Returns:
    Filtered URL results with duplicates removed

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

TOOL_NAME = "uro_url_filtering"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    urls = params.get("urls", "")
    whitelist = params.get("whitelist", "")
    blacklist = params.get("blacklist", "")
    additional_args = params.get("additional_args", "")
    command = f"echo '{urls}' | uro"
    if whitelist:
        command += f" --whitelist {whitelist}"
    if blacklist:
        command += f" --blacklist {blacklist}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(urls: str = '', whitelist: str = '', blacklist: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"urls": urls, "whitelist": whitelist, "blacklist": blacklist, "additional_args": additional_args}
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
