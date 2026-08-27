"""
Execute Hashcat for advanced password cracking with enhanced logging.

Args:
    hash_file: File containing password hashes
    hash_type: Hash type number for Hashcat
    attack_mode: Attack mode (0=dict, 1=combo, 3=mask, etc.)
    wordlist: Wordlist file for dictionary attacks
    mask: Mask for mask attacks
    additional_args: Additional Hashcat arguments

Returns:
    Password cracking results

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

TOOL_NAME = "hashcat_crack"
CATEGORY = "creds"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    hash_file = params.get("hash_file", "")
    hash_type = params.get("hash_type", "")
    attack_mode = params.get("attack_mode", "0")
    wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    mask = params.get("mask", "")
    additional_args = params.get("additional_args", "")
    command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file}"
    if attack_mode == "0" and wordlist:
        command += f" {wordlist}"
        command += f" {mask}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(hash_file: str = '', hash_type: str = '', attack_mode: str = '0', wordlist: str = '/usr/share/wordlists/rockyou.txt', mask: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"hash_file": hash_file, "hash_type": hash_type, "attack_mode": attack_mode, "wordlist": wordlist, "mask": mask, "additional_args": additional_args}
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
