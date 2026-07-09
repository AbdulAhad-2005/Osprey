"""
Execute kube-bench for CIS Kubernetes benchmark checks.

Args:
    targets: Targets to check (master, node, etcd, policies)
    version: Kubernetes version
    config_dir: Configuration directory
    output_format: Output format (json, yaml)
    additional_args: Additional kube-bench arguments

Returns:
    CIS Kubernetes benchmark results

Harvested: HexStrike `kube_bench_cis` -> `/api/tools/kube-bench`.
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

TOOL_NAME = "kube_bench_cis"
CATEGORY = "cloud"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    targets = params.get("targets", "")  # master, node, etcd, policies
    version = params.get("version", "")
    config_dir = params.get("config_dir", "")
    output_format = params.get("output_format", "json")
    additional_args = params.get("additional_args", "")
    command = "kube-bench"
    if targets:
        command += f" --targets {targets}"
    if version:
        command += f" --version {version}"
    if config_dir:
        command += f" --config-dir {config_dir}"
    if output_format:
        command += f" --outputfile /tmp/kube-bench-results.{output_format} --json"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(targets: str = '', version: str = '', config_dir: str = '', output_format: str = 'json', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"targets": targets, "version": version, "config_dir": config_dir, "output_format": output_format, "additional_args": additional_args}
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
