"""
Execute Prowler for comprehensive cloud security assessment.

Args:
    provider: Cloud provider (aws, azure, gcp)
    profile: AWS profile to use
    region: Specific region to scan
    checks: Specific checks to run
    output_dir: Directory to save results
    output_format: Output format (json, csv, html)
    additional_args: Additional Prowler arguments

Returns:
    Cloud security assessment results

Harvested: HexStrike `prowler_scan` -> `/api/tools/prowler`.
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

TOOL_NAME = "prowler_scan"
CATEGORY = "cloud"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    provider = params.get("provider", "aws")
    profile = params.get("profile", "default")
    region = params.get("region", "")
    checks = params.get("checks", "")
    output_dir = params.get("output_dir", "/tmp/prowler_output")
    output_format = params.get("output_format", "json")
    additional_args = params.get("additional_args", "")
    command = f"prowler {provider}"
    if profile:
        command += f" --profile {profile}"
    if region:
        command += f" --region {region}"
    if checks:
        command += f" --checks {checks}"
    command += f" --output-directory {output_dir}"
    command += f" --output-format {output_format}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(provider: str = 'aws', profile: str = 'default', region: str = '', checks: str = '', output_dir: str = '/tmp/prowler_output', output_format: str = 'json', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"provider": provider, "profile": profile, "region": region, "checks": checks, "output_dir": output_dir, "output_format": output_format, "additional_args": additional_args}
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
