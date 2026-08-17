"""
Passive Shodan host/search OSINT (API). Requires SHODAN_API_KEY in Kali env.

Args:
    query: Shodan search query (hostname:, ssl:, org:, port:, product:, …)
    domain: Convenience — becomes hostname:<domain> when query is empty
    target: Alias for domain/query when LLM passes target=
    limit: Max matches to return (1–100, default 20)
    additional_args: Unused passthrough for platform freeform field

Category: recon
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "shodan_search"
CATEGORY = "recon"

# Runtime-resolved in the shell (inside the Kali container where the filesystem
# is real): commands are built in the backend but executed via docker exec.
_CLI_CONTAINER = "/home/mcpuser/mcp-servers/recon/tools/_shodan_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_shodan_cli.py"))

def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def build_command(**params: Any) -> str:
    query = str(params.get("query") or "").strip()
    domain = str(params.get("domain") or "").strip()
    target = str(params.get("target") or "").strip()
    limit = params.get("limit", 20)

    if not query:
        seed = domain or target
        if seed and _IP_RE.match(seed):
            # Misrouted host lookup — still useful via hostname/ip search
            query = f"ip:{seed}"
        elif seed:
            query = f"hostname:{seed}"

    if not query:
        raise ValueError("shodan_search requires query= or domain=/target=")

    return (
        f"python3 {_cli_expr()} search "
        f"{shlex.quote(query)} {shlex.quote(str(limit))}"
    )


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    query: str = "",
    domain: str = "",
    target: str = "",
    limit: int = 20,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 90,
) -> dict[str, Any]:
    params = {
        "query": query,
        "domain": domain,
        "target": target,
        "limit": limit,
        "additional_args": additional_args,
    }
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
