"""
Execute HashPump for hash length extension attacks with enhanced logging.

Args:
    signature: Original hash signature
    data: Original data
    key_length: Length of secret key
    append_data: Data to append
    additional_args: Additional HashPump arguments

Returns:
    Hash length extension attack results

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

TOOL_NAME = "hashpump_attack"
CATEGORY = "forensics"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    signature = params.get("signature", "")
    data = params.get("data", "")
    key_length = params.get("key_length", "")
    append_data = params.get("append_data", "")
    additional_args = params.get("additional_args", "")
    command = f"hashpump -s {signature} -d '{data}' -k {key_length} -a '{append_data}'"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(signature: str = '', data: str = '', key_length: str = '', append_data: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"signature": signature, "data": data, "key_length": key_length, "append_data": append_data, "additional_args": additional_args}
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
