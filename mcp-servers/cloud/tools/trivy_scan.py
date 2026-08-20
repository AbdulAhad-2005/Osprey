"""
Execute Trivy for container and filesystem vulnerability scanning.

Args:
    scan_type: Type of scan (image, fs, repo, config)
    target: Target to scan (image name, directory, repository)
    output_format: Output format (json, table, sarif)
    severity: Severity filter (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)
    output_file: File to save results
    additional_args: Additional Trivy arguments

Returns:
    Vulnerability scan results

Harvested: HexStrike `trivy_scan` -> `/api/tools/trivy`.
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
from _core.command_utils import q

TOOL_NAME = "trivy_scan"
CATEGORY = "cloud"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    scan_type = params.get("scan_type", "image")  # image, fs, repo
    target = params.get("target", "")
    output_format = params.get("output_format", "json")
    severity = params.get("severity", "")
    output_file = params.get("output_file", "")
    additional_args = params.get("additional_args", "")
    command = f"trivy {scan_type} {q(target)}"
    if output_format:
        command += f" --format {output_format}"
    if severity:
        command += f" --severity {severity}"
    if output_file:
        command += f" --output {output_file}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(scan_type: str = 'image', target: str = '', output_format: str = 'json', severity: str = '', output_file: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"scan_type": scan_type, "target": target, "output_format": output_format, "severity": severity, "output_file": output_file, "additional_args": additional_args}
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
