"""
Execute Falco for runtime security monitoring.

Args:
    config_file: Falco configuration file
    rules_file: Custom rules file
    output_format: Output format (json, text)
    duration: Monitoring duration in seconds
    additional_args: Additional Falco arguments

Returns:
    Runtime security monitoring results

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

TOOL_NAME = "falco_runtime_monitoring"
CATEGORY = "cloud"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    config_file = params.get("config_file", "/etc/falco/falco.yaml")
    rules_file = params.get("rules_file", "")
    output_format = params.get("output_format", "json")
    duration = params.get("duration", 60)  # seconds
    additional_args = params.get("additional_args", "")
    command = f"timeout {duration} falco"
    if config_file:
        command += f" --config {config_file}"
    if rules_file:
        command += f" --rules {rules_file}"
    if output_format == "json":
        command += " --json"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(config_file: str = '/etc/falco/falco.yaml', rules_file: str = '', output_format: str = 'json', duration: int = 60, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"config_file": config_file, "rules_file": rules_file, "output_format": output_format, "duration": duration, "additional_args": additional_args}
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
