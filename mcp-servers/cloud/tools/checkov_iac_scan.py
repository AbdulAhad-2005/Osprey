"""
Execute Checkov for infrastructure as code security scanning.

Args:
    directory: Directory to scan
    framework: Framework to scan (terraform, cloudformation, kubernetes, etc.)
    check: Specific check to run
    skip_check: Check to skip
    output_format: Output format (json, yaml, cli)
    additional_args: Additional Checkov arguments

Returns:
    Infrastructure as code security scanning results

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

TOOL_NAME = "checkov_iac_scan"
CATEGORY = "cloud"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    directory = params.get("directory", ".")
    framework = params.get("framework", "")  # terraform, cloudformation, kubernetes, etc.
    check = params.get("check", "")
    skip_check = params.get("skip_check", "")
    output_format = params.get("output_format", "json")
    additional_args = params.get("additional_args", "")
    command = f"checkov -d {directory}"
    if framework:
        command += f" --framework {framework}"
    if check:
        command += f" --check {check}"
    if skip_check:
        command += f" --skip-check {skip_check}"
    if output_format:
        command += f" --output {output_format}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(directory: str = '.', framework: str = '', check: str = '', skip_check: str = '', output_format: str = 'json', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"directory": directory, "framework": framework, "check": check, "skip_check": skip_check, "output_format": output_format, "additional_args": additional_args}
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
