"""
Execute HTTPx for HTTP probing with enhanced logging.

Args:
    targets: Target URLs or IPs
    target_file: File containing targets
    ports: Ports to probe
    methods: HTTP methods to use
    status_code: Filter by status code
    content_length: Show content length
    output_file: Output file path
    additional_args: Additional HTTPx arguments

Returns:
    HTTP probing results

Harvested: HexStrike `httpx_probe` -> `/api/tools/httpx`.
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

TOOL_NAME = "httpx_probe"
CATEGORY = "recon"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    target = params.get("target", "")
    probe = params.get("probe", True)
    tech_detect = params.get("tech_detect", False)
    status_code = params.get("status_code", False)
    content_length = params.get("content_length", False)
    title = params.get("title", False)
    web_server = params.get("web_server", False)
    threads = params.get("threads", 50)
    additional_args = params.get("additional_args", "")

    import os
    is_file = os.path.isfile(target) if target else False

    if is_file:
        command = f"httpx -l {target} -t {threads}"
    elif "\n" in target:
        targets = [t.strip() for t in target.strip().splitlines() if t.strip()]
        joined = "\\n".join(targets)
        command = f"echo -e '{joined}' | httpx -t {threads}"
    else:
        command = f"httpx -u {target} -t {threads}"

    if probe:
        command += " -probe"
    if tech_detect:
        command += " -tech-detect"
    if status_code:
        command += " -sc"
    if content_length:
        command += " -cl"
    if title:
        command += " -title"
    if web_server:
        command += " -server"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', probe: bool = True, tech_detect: bool = False, status_code: bool = False, content_length: bool = False, title: bool = False, web_server: bool = False, threads: int = 50, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "probe": probe, "tech_detect": tech_detect, "status_code": status_code, "content_length": content_length, "title": title, "web_server": web_server, "threads": threads, "additional_args": additional_args}
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
