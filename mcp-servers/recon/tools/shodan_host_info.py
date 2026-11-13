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

# Runtime-resolved in the shell (inside the Kali container where the filesystem
# is real): commands are built in the backend but executed via docker exec.
_CLI_CONTAINER = "/home/mcpuser/mcp-servers/recon/tools/_shodan_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_shodan_cli.py"))

def _cli_expr() -> str:
    # Double-quoted at BOTH levels: the inner echo args (so a fallback path
    # with spaces, e.g. a Windows checkout path, survives as one shell word
    # going in) AND the outer $(...) substitution itself (bash word-splits a
    # command substitution's *output* on whitespace at its point of use
    # regardless of how the inner command was quoted).
    container, fallback = shlex.quote(_CLI_CONTAINER), shlex.quote(_CLI_FALLBACK)
    return f'"$( [ -f {container} ] && echo {container} || echo {fallback} )"'


def build_command(**params: Any) -> str:
    ip = str(params.get("ip") or params.get("target") or params.get("host") or "").strip()
    if not ip:
        raise ValueError("shodan_host_info requires ip= or target=")
    return f"python3 {_cli_expr()} host {shlex.quote(ip)}"


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
