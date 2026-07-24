"""
Passive Shodan host detail by IP (API). Requires SHODAN_API_KEY in Kali env.

Args:
    ip: Target IPv4 address
    target: Alias for ip when LLM passes target=
    additional_args: Unused passthrough for platform freeform field

Category: recon
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "shodan_host_info"
CATEGORY = "recon"

_CLI = "/home/mcpuser/mcp-servers/recon/tools/_shodan_cli.py"


def build_command(**params: Any) -> str:
    ip = str(params.get("ip") or params.get("target") or params.get("host") or "").strip()
    if not ip:
        raise ValueError("shodan_host_info requires ip= or target=")
    return f"python3 {shlex.quote(_CLI)} host {shlex.quote(ip)}"


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    ip: str = "",
    target: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 60,
) -> dict[str, Any]:
    params = {"ip": ip, "target": target, "additional_args": additional_args}
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
