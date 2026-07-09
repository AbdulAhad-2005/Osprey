"""
Execute ParamSpider for parameter discovery with enhanced logging.

Args:
    domain: Target domain
    exclude: Extensions to exclude
    output_file: Output file path
    level: Crawling level
    additional_args: Additional ParamSpider arguments

Returns:
    Parameter discovery results

Harvested: HexStrike `paramspider_discovery` -> `/api/tools/paramspider`.
Category: web
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

TOOL_NAME = "paramspider_discovery"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    domain = params.get("domain", "")
    level = params.get("level", 2)
    exclude = params.get("exclude", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
    output = params.get("output", "")
    additional_args = params.get("additional_args", "")
    command = f"paramspider -d {domain} -l {level}"
    if exclude:
        command += f" --exclude {exclude}"
    if output:
        command += f" -o {output}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(domain: str = '', level: int = 2, exclude: str = 'png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico', output: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"domain": domain, "level": level, "exclude": exclude, "output": output, "additional_args": additional_args}
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
