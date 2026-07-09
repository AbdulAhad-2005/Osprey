"""
Execute John the Ripper for password cracking with enhanced logging.

Args:
    hash_file: File containing password hashes
    wordlist: Wordlist file to use
    format_type: Hash format type
    additional_args: Additional John arguments

Returns:
    Password cracking results

Harvested: HexStrike `john_crack` -> `/api/tools/john`.
Category: creds
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

TOOL_NAME = "john_crack"
CATEGORY = "creds"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    hash_file = params.get("hash_file", "")
    wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    format_type = params.get("format", "")
    additional_args = params.get("additional_args", "")
    command = f"john"
    if format_type:
        command += f" --format={format_type}"
    if wordlist:
        command += f" --wordlist={wordlist}"
    if additional_args:
        command += f" {additional_args}"
    command += f" {hash_file}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(hash_file: str = '', wordlist: str = '/usr/share/wordlists/rockyou.txt', format: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"hash_file": hash_file, "wordlist": wordlist, "format": format, "additional_args": additional_args}
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
