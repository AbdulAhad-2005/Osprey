"""
Execute Terrascan for infrastructure as code security scanning.

Args:
    scan_type: Type of scan (all, terraform, k8s, etc.)
    iac_dir: Infrastructure as code directory
    policy_type: Policy type to use
    output_format: Output format (json, yaml, xml)
    severity: Severity filter (high, medium, low)
    additional_args: Additional Terrascan arguments

Returns:
    Infrastructure as code security scanning results

Harvested: HexStrike `terrascan_iac_scan` -> `/api/tools/terrascan`.
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

TOOL_NAME = "terrascan_iac_scan"
CATEGORY = "cloud"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    scan_type = params.get("scan_type", "all")  # all, terraform, k8s, etc.
    iac_dir = params.get("iac_dir", ".")
    policy_type = params.get("policy_type", "")
    output_format = params.get("output_format", "json")
    severity = params.get("severity", "")
    additional_args = params.get("additional_args", "")
    command = f"terrascan scan -t {scan_type} -d {iac_dir}"
    if policy_type:
        command += f" -p {policy_type}"
    if output_format:
        command += f" -o {output_format}"
    if severity:
        command += f" --severity {severity}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(scan_type: str = 'all', iac_dir: str = '.', policy_type: str = '', output_format: str = 'json', severity: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"scan_type": scan_type, "iac_dir": iac_dir, "policy_type": policy_type, "output_format": output_format, "severity": severity, "additional_args": additional_args}
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
