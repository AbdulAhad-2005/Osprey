"""
Execute Steghide for steganography analysis with enhanced logging.

Args:
    action: Action to perform (extract, embed, info)
    cover_file: Cover file for steganography
    embed_file: File to embed (for embed action)
    passphrase: Passphrase for steganography
    output_file: Output file path
    additional_args: Additional Steghide arguments

Returns:
    Steganography analysis results

Harvested: HexStrike `steghide_analysis` -> `/api/tools/steghide`.
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

TOOL_NAME = "steghide_analysis"
CATEGORY = "forensics"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    action = params.get("action", "extract")  # extract, embed, info
    cover_file = params.get("cover_file", "")
    embed_file = params.get("embed_file", "")
    passphrase = params.get("passphrase", "")
    output_file = params.get("output_file", "")
    additional_args = params.get("additional_args", "")
    if action == "extract":
        command = f"steghide extract -sf {cover_file}"
        if output_file:
            command += f" -xf {output_file}"
        command = f"steghide embed -cf {cover_file} -ef {embed_file}"
        command = f"steghide info {cover_file}"
    if passphrase:
        command += f" -p {passphrase}"
        command += " -p ''"  # Empty passphrase
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(action: str = 'extract', cover_file: str = '', embed_file: str = '', passphrase: str = '', output_file: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"action": action, "cover_file": cover_file, "embed_file": embed_file, "passphrase": passphrase, "output_file": output_file, "additional_args": additional_args}
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
