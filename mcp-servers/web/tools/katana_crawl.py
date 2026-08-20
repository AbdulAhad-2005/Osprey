"""
Execute Katana for next-generation crawling and spidering with enhanced logging.

Args:
    url: The target URL to crawl
    depth: Crawling depth
    js_crawl: Enable JavaScript crawling
    form_extraction: Enable form extraction
    output_format: Output format (json, txt)
    additional_args: Additional Katana arguments

Returns:
    Advanced web crawling results with endpoints and forms

Harvested: HexStrike `katana_crawl` -> `/api/tools/katana`.
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
from _core.command_utils import q

TOOL_NAME = "katana_crawl"
CATEGORY = "web"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    url = params.get("url", "")
    depth = params.get("depth", 3)
    js_crawl = params.get("js_crawl", True)
    form_extraction = params.get("form_extraction", True)
    output_format = params.get("output_format", "json")
    # Headless rendering: drive a real Chromium so JS-built SPA routes, forms and
    # XHR/fetch endpoints are actually discovered (static -jc parsing misses the
    # DOM a React/Vue/Angular app builds client-side). -no-sandbox is required
    # when running as the container user. -xhr captures in-page API calls.
    headless = str(params.get("headless", "")).strip().lower() in ("1", "true", "yes", "on")
    no_sandbox = str(params.get("no_sandbox", "true")).strip().lower() in ("1", "true", "yes", "on")
    additional_args = str(params.get("additional_args", "") or "")
    command = f"katana -u {q(url)} -d {depth}"
    if js_crawl:
        command += " -jc"
    if form_extraction:
        command += " -fx"
    if headless and "-headless" not in additional_args and " -hl" not in additional_args:
        command += " -headless -xhr"
        if no_sandbox:
            command += " -no-sandbox"
    if output_format == "json":
        command += " -jsonl"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', depth: int = 3, js_crawl: bool = True, form_extraction: bool = True, output_format: str = 'json', headless: bool = False, no_sandbox: bool = True, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "depth": depth, "js_crawl": js_crawl, "form_extraction": form_extraction, "output_format": output_format, "headless": headless, "no_sandbox": no_sandbox, "additional_args": additional_args}
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
