"""
Intelligence X (intelx.io) credential + identity harvest for a domain/selector.

Passive breach-intel lookup: the phonebook mode harvests emails / subdomains /
URLs from IntelX's index; the leaks mode (needs INTELX_IDENTITY_API_KEY) pulls
actual leaked account records (user + password). The backend `parse_intelx`
mints typed EMAIL / SUBDOMAIN / CREDENTIAL findings — leaked creds are stored as
INFERRED leads (breach data, not verified against the live target), below any
credential scraped directly during the engagement.

Args:
    target: Domain / email / selector to look up (alias: domain)
    mode: phonebook | leaks | all (default all)
    limit: Max results (default 200)

Category: osint

Requires INTELX_API_KEY (phonebook) and optionally INTELX_IDENTITY_API_KEY
(leaked credentials) in the Kali/host env.
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

TOOL_NAME = "intelx_scan"
CATEGORY = "osint"

_CLI_CONTAINER = "/home/mcpuser/mcp-servers/osint/tools/_intelx_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_intelx_cli.py"))

_MODES = {"phonebook", "leaks", "all"}


def _cli_expr() -> str:
    return f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} || echo {_CLI_FALLBACK} )"


def build_command(**params: Any) -> str:
    term = str(params.get("target") or params.get("domain") or params.get("selector") or "").strip()
    if not term:
        raise ValueError("intelx_scan requires target= (domain / email / selector)")
    mode = str(params.get("mode") or "all").strip().lower()
    if mode not in _MODES:
        mode = "all"
    limit = str(params.get("limit") or 200).strip()
    return f"python3 {_cli_expr()} {mode} {shlex.quote(term)} {shlex.quote(limit)}"


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    target: str = "",
    domain: str = "",
    mode: str = "all",
    limit: int = 200,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 120,
) -> dict[str, Any]:
    params = {"target": target, "domain": domain, "mode": mode, "limit": limit}
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
