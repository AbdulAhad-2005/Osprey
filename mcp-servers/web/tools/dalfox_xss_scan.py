"""
Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging.

Args:
    url: The target URL
    pipe_mode: Use pipe mode for input
    blind: Enable blind XSS testing
    mining_dom: Enable DOM mining
    mining_dict: Enable dictionary mining
    custom_payload: Custom XSS payload
    additional_args: Additional Dalfox arguments

Returns:
    Advanced XSS vulnerability scanning results

Harvested: HexStrike `dalfox_xss_scan` -> `/api/tools/dalfox`.
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

TOOL_NAME = "dalfox_xss_scan"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    url = params.get("url", "")
    pipe_mode = params.get("pipe_mode", False)
    blind = params.get("blind", False)
    mining_dom = params.get("mining_dom", True)
    mining_dict = params.get("mining_dict", True)
    custom_payload = params.get("custom_payload", "")
    additional_args = str(params.get("additional_args", "") or "")
    command = "dalfox pipe" if pipe_mode else f"dalfox url {url}"
    if blind:
        command += " --blind"
    if mining_dom:
        command += " --mining-dom"
    if mining_dict:
        command += " --mining-dict"
    if custom_payload:
        command += f" --custom-payload '{custom_payload}'"
    # JSON output so the backend parser gets structured PoC/param/severity data.
    if "--format" not in additional_args and "-F " not in additional_args:
        command += " --format json --silence"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', pipe_mode: bool = False, blind: bool = False, mining_dom: bool = True, mining_dict: bool = True, custom_payload: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "pipe_mode": pipe_mode, "blind": blind, "mining_dom": mining_dom, "mining_dict": mining_dict, "custom_payload": custom_payload, "additional_args": additional_args}
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
