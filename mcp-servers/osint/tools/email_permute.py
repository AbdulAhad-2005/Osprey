"""
Email permutation — turn a discovered NAME + a domain into likely corporate email
candidates, and report whether the domain accepts mail (MX). Keyless.

Pivot helper: web_contact_harvest / theHarvester find a name → this proposes the
addresses → holehe tests which actually exist.

Args:
    name: Full person name (e.g. "Jane Doe")
    domain: Corporate domain (e.g. example.com)
    target: Alias for domain
    additional_args: Unused passthrough

Category: osint

Candidates are hypotheses (evidence_grade inferred) until confirmed by holehe/SMTP.
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

TOOL_NAME = "email_permute"
CATEGORY = "osint"

# Runtime-resolved in the shell (inside the Kali container where the filesystem
# is real): commands are built in the backend but executed via docker exec.
_CLI_CONTAINER = "/home/mcpuser/mcp-servers/osint/tools/_email_permute_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_email_permute_cli.py"))

def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )


def build_command(**params: Any) -> str:
    name = str(params.get("name") or "").strip()
    domain = str(params.get("domain") or params.get("target") or "").strip()

    if not name or not domain:
        raise ValueError("email_permute requires name= and domain= (or target=)")

    return (
        f"python3 {_cli_expr()} "
        f"{shlex.quote(name)} {shlex.quote(domain)}"
    )


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        data = json.loads(raw)
        return {"candidates": len(data.get("candidates", [])), "mx": data.get("mx")}
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:300]}


def run(
    name: str = "",
    domain: str = "",
    target: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 60,
) -> dict[str, Any]:
    params = {"name": name, "domain": domain, "target": target}
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
