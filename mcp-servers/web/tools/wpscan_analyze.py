"""
Execute WPScan for WordPress vulnerability scanning with enhanced logging.

Args:
    url: The WordPress site URL
    additional_args: Additional WPScan arguments

Returns:
    WordPress vulnerability scan results

Harvested: HexStrike `wpscan_analyze` -> `/api/tools/wpscan`.
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

TOOL_NAME = "wpscan_analyze"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    url = params.get("url", "")
    additional_args = str(params.get("additional_args", "") or "")
    command = f"wpscan --url {url}"
    # JSON output + no banner so the backend parser gets structured
    # version/plugin/vuln data instead of scraping the CLI report.
    if "--format" not in additional_args and "-f " not in additional_args:
        command += " --format json --no-banner"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "additional_args": additional_args}
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
