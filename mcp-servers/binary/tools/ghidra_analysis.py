"""
Execute Ghidra for advanced binary analysis and reverse engineering.

Args:
    binary: Path to the binary file
    project_name: Ghidra project name
    script_file: Custom Ghidra script to run
    analysis_timeout: Analysis timeout in seconds
    output_format: Output format (xml, json)
    additional_args: Additional Ghidra arguments

Returns:
    Advanced binary analysis results from Ghidra

Harvested: HexStrike `ghidra_analysis` -> `/api/tools/ghidra`.
Category: binary
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

TOOL_NAME = "ghidra_analysis"
CATEGORY = "binary"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    binary = params.get("binary", "")
    project_name = params.get("project_name", "hexstrike_analysis")
    script_file = params.get("script_file", "")
    analysis_timeout = params.get("analysis_timeout", 300)
    output_format = params.get("output_format", "xml")
    additional_args = params.get("additional_args", "")
    project_dir = params.get("project_dir", "")
    if not project_dir and binary:
        project_dir = str(Path(binary).resolve().parent)
    if not project_dir:
        project_dir = "/tmp/ghidra_projects"
    # Base Ghidra command for headless analysis
    command = f"analyzeHeadless {project_dir} {project_name} -import {binary} -deleteProject"
    if script_file:
        command += f" -postScript {script_file}"
    if output_format == "xml":
        command += f" -postScript ExportXml.java {project_dir}/analysis.xml"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(binary: str = '', project_name: str = 'hexstrike_analysis', script_file: str = '', analysis_timeout: int = 300, output_format: str = 'xml', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"binary": binary, "project_name": project_name, "script_file": script_file, "analysis_timeout": analysis_timeout, "output_format": output_format, "additional_args": additional_args}
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
