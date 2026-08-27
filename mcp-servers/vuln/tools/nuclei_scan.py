"""
Execute Nuclei vulnerability scanner with enhanced logging and real-time progress.

Args:
    target: The target URL or IP
    severity: Filter by severity (critical,high,medium,low,info)
    tags: Filter by tags (e.g. cve,rce,lfi)
    template: Custom template path
    additional_args: Additional Nuclei arguments

Returns:
    Scan results with discovered vulnerabilities and telemetry

Category: vuln
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.command_utils import q
from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "nuclei_scan"
CATEGORY = "vuln"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    target = params.get("target", "")
    severity = params.get("severity", "")
    tags = params.get("tags", "")
    template = params.get("template", "")
    additional_args = str(params.get("additional_args", "") or "")
    command = f"nuclei -u {q(target)}"
    if severity:
        command += f" -severity {q(severity)}"
    if tags:
        command += f" -tags {q(tags)}"
    if template:
        command += f" -t {q(template)}"
    # Structured JSONL output so the backend parser gets template-id / severity /
    # CVE / matched-at reliably. -silent suppresses the banner/progress noise.
    if not any(f in additional_args for f in ("-jsonl", "-json", "-j ", "-je", "-jsone")):
        command += " -jsonl -silent"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', severity: str = '', tags: str = '', template: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "severity": severity, "tags": tags, "template": template, "additional_args": additional_args}
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
