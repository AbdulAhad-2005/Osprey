"""
Resecurity credential-intel lookup for a domain / email / selector.

Passive breach-intel: queries your configured Resecurity endpoint and returns
leaked credentials + emails. The backend `parse_resecurity` mints typed
CREDENTIAL / EMAIL findings; leaked creds are stored intact and graded as
INFERRED breach leads (below anything scraped live during the engagement).

Args:
    target: Domain / email / selector to look up (alias: domain)
    limit: Max results (default 100)

Category: osint

Requires RESECURITY_API_KEY (and optionally RESECURITY_API_BASE /
RESECURITY_ENDPOINT for your account) in the Kali/host env.
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

TOOL_NAME = "resecurity_scan"
CATEGORY = "osint"

_CLI_CONTAINER = "/home/mcpuser/mcp-servers/osint/tools/_resecurity_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_resecurity_cli.py"))


def _cli_expr() -> str:
    return f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} || echo {_CLI_FALLBACK} )"


def build_command(**params: Any) -> str:
    term = str(params.get("target") or params.get("domain") or params.get("selector") or "").strip()
    if not term:
        raise ValueError("resecurity_scan requires target= (domain / email / selector)")
    limit = str(params.get("limit") or 100).strip()
    return f"python3 {_cli_expr()} search {shlex.quote(term)} {shlex.quote(limit)}"


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    target: str = "",
    domain: str = "",
    limit: int = 100,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 90,
) -> dict[str, Any]:
    params = {"target": target, "domain": domain, "limit": limit}
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
