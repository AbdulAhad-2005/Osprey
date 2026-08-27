"""
Execute Dirsearch for advanced directory and file discovery with enhanced logging.

Args:
    url: The target URL
    extensions: File extensions to search for
    wordlist: Wordlist file to use
    threads: Number of threads to use
    recursive: Enable recursive scanning
    additional_args: Additional Dirsearch arguments

Returns:
    Advanced directory discovery results

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

TOOL_NAME = "dirsearch_scan"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    url = params.get("url", "")
    extensions = params.get("extensions", "php,html,js,txt,xml,json")
    wordlist = params.get("wordlist", "/usr/share/wordlists/dirsearch/common.txt")
    threads = params.get("threads", 30)
    recursive = params.get("recursive", False)
    additional_args = params.get("additional_args", "")
    command = f"dirsearch -u {q(url)} -e {extensions} -w {wordlist} -t {threads}"
    if recursive:
        command += " -r"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', extensions: str = 'php,html,js,txt,xml,json', wordlist: str = '/usr/share/wordlists/dirsearch/common.txt', threads: int = 30, recursive: bool = False, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "extensions": extensions, "wordlist": wordlist, "threads": threads, "recursive": recursive, "additional_args": additional_args}
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
