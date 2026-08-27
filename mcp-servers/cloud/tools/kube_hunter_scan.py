"""
Execute kube-hunter for Kubernetes penetration testing.

Args:
    target: Specific target to scan
    remote: Remote target to scan
    cidr: CIDR range to scan
    interface: Network interface to scan
    active: Enable active hunting (potentially harmful)
    report: Report format (json, yaml)
    additional_args: Additional kube-hunter arguments

Returns:
    Kubernetes penetration testing results

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

TOOL_NAME = "kube_hunter_scan"
CATEGORY = "cloud"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    target = params.get("target", "")
    remote = params.get("remote", "")
    cidr = params.get("cidr", "")
    interface = params.get("interface", "")
    active = params.get("active", False)
    report = params.get("report", "json")
    additional_args = params.get("additional_args", "")
    command = "kube-hunter"
    if target:
        command += f" --remote {q(target)}"
        command += f" --remote {q(remote)}"
        command += f" --cidr {q(cidr)}"
        command += f" --interface {q(interface)}"
        command += " --pod"
    if active:
        command += " --active"
    if report:
        command += f" --report {report}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', remote: str = '', cidr: str = '', interface: str = '', active: bool = False, report: str = 'json', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "remote": remote, "cidr": cidr, "interface": interface, "active": active, "report": report, "additional_args": additional_args}
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
