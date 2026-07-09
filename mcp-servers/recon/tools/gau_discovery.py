"""
Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging.

Args:
    domain: The target domain
    providers: Data providers to use
    include_subs: Include subdomains
    blacklist: File extensions to blacklist
    additional_args: Additional Gau arguments

Returns:
    Comprehensive URL discovery results from multiple sources

Harvested: HexStrike `gau_discovery` -> `/api/tools/gau`.
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

TOOL_NAME = "gau_discovery"
CATEGORY = "recon"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    domain = params.get("domain", "")
    providers = params.get("providers", "wayback,commoncrawl,otx,urlscan")
    include_subs = params.get("include_subs", True)
    blacklist = params.get("blacklist", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
    additional_args = params.get("additional_args", "")
    command = f"gau {domain}"
    if providers != "wayback,commoncrawl,otx,urlscan":
        command += f" --providers {providers}"
    if include_subs:
        command += " --subs"
    if blacklist:
        command += f" --blacklist {blacklist}"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(domain: str = '', providers: str = 'wayback,commoncrawl,otx,urlscan', include_subs: bool = True, blacklist: str = 'png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"domain": domain, "providers": providers, "include_subs": include_subs, "blacklist": blacklist, "additional_args": additional_args}
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
