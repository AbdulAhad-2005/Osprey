"""
Execute Scout Suite for multi-cloud security assessment.

Args:
    provider: Cloud provider (aws, azure, gcp, aliyun, oci)
    profile: AWS profile to use
    report_dir: Directory to save reports
    services: Specific services to assess
    exceptions: Exceptions file path
    additional_args: Additional Scout Suite arguments

Returns:
    Multi-cloud security assessment results

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

TOOL_NAME = "scout_suite_assessment"
CATEGORY = "cloud"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    provider = params.get("provider", "aws")  # aws, azure, gcp, aliyun, oci
    profile = params.get("profile", "default")
    report_dir = params.get("report_dir", "/tmp/scout-suite")
    services = params.get("services", "")
    exceptions = params.get("exceptions", "")
    additional_args = params.get("additional_args", "")
    command = f"scout {provider}"
    if profile and provider == "aws":
        command += f" --profile {profile}"
    if services:
        command += f" --services {services}"
    if exceptions:
        command += f" --exceptions {exceptions}"
    command += f" --report-dir {report_dir}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(provider: str = 'aws', profile: str = 'default', report_dir: str = '/tmp/scout-suite', services: str = '', exceptions: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"provider": provider, "profile": profile, "report_dir": report_dir, "services": services, "exceptions": exceptions, "additional_args": additional_args}
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
