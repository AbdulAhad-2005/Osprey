"""
Execute CloudMapper for AWS network visualization and security analysis.

Args:
    action: Action to perform (collect, prepare, webserver, find_admins, etc.)
    account: AWS account to analyze
    config: Configuration file path
    additional_args: Additional CloudMapper arguments

Returns:
    AWS network visualization and security analysis results

Category: cloud
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

TOOL_NAME = "cloudmapper_analysis"
CATEGORY = "cloud"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    action = params.get("action", "collect")  # collect, prepare, webserver, find_admins, etc.
    account = params.get("account", "")
    config = params.get("config", "config.json")
    additional_args = params.get("additional_args", "")
    command = f"cloudmapper {action}"
    if account:
        command += f" --account {account}"
    if config:
        command += f" --config {config}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(action: str = 'collect', account: str = '', config: str = 'config.json', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"action": action, "account": account, "config": config, "additional_args": additional_args}
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
