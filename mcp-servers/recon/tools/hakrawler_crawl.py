"""
Execute Hakrawler for web endpoint discovery with enhanced logging.

Note: Uses standard Kali Linux hakrawler (hakluke/hakrawler) with parameter mapping:
- url: Piped via echo to stdin (not -url flag)
- depth: Mapped to -d flag (not -depth)
- forms: Mapped to -s flag for showing sources
- robots/sitemap/wayback: Mapped to -subs for subdomain inclusion
- Always includes -u for unique URLs

Args:
    url: Target URL to crawl
    depth: Crawling depth (mapped to -d)
    forms: Include forms in crawling (mapped to -s)
    robots: Check robots.txt (mapped to -subs)
    sitemap: Check sitemap.xml (mapped to -subs)
    wayback: Use Wayback Machine (mapped to -subs)
    additional_args: Additional Hakrawler arguments

Returns:
    Web endpoint discovery results

Category: recon
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

TOOL_NAME = "hakrawler_crawl"
CATEGORY = "recon"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    url = params.get("url", "")
    depth = params.get("depth", 2)
    forms = params.get("forms", True)
    robots = params.get("robots", True)
    sitemap = params.get("sitemap", True)
    wayback = params.get("wayback", False)
    additional_args = params.get("additional_args", "")
    # Build command for standard Kali Linux hakrawler (hakluke version)
    command = f"echo '{url}' | hakrawler -d {depth}"
    if forms:
        command += " -s"  # Show sources (includes forms)
    if robots or sitemap or wayback:
        command += " -subs"  # Include subdomains for better coverage
    command += " -u"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', depth: int = 2, forms: bool = True, robots: bool = True, sitemap: bool = True, wayback: bool = False, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "depth": depth, "forms": forms, "robots": robots, "sitemap": sitemap, "wayback": wayback, "additional_args": additional_args}
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
