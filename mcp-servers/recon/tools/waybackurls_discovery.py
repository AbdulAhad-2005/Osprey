"""
Execute Waybackurls for historical URL discovery with enhanced logging.

Args:
    domain: The target domain
    get_versions: Get all versions of URLs
    no_subs: Don't include subdomains
    additional_args: Additional Waybackurls arguments

Returns:
    Historical URL discovery results from Wayback Machine

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
from _core.command_utils import q

TOOL_NAME = "waybackurls_discovery"
CATEGORY = "recon"

def build_command(**params: Any) -> str:
    """Build CLI command."""
    domain = params.get("domain", "")
    get_versions = params.get("get_versions", False)
    no_subs = params.get("no_subs", False)
    additional_args = params.get("additional_args", "")
    command = f"waybackurls {q(domain)}"
    if get_versions:
        command += " --get-versions"
    if no_subs:
        command += " --no-subs"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(domain: str = '', get_versions: bool = False, no_subs: bool = False, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"domain": domain, "get_versions": get_versions, "no_subs": no_subs, "additional_args": additional_args}
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
