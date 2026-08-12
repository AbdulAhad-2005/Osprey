"""
Check hosts for dangling CNAME / unclaimed SaaS takeover fingerprints.

Args:
    target: Single hostname (mode=single) or seed when providing subdomains list
    mode: single | list (default single). Prefer list after subdomain enum.
    subdomains: Newline/comma-separated host list for mode=list
    max_hosts: Soft cap (default 50) — chunk with jobs for large inventories
    additional_args: Unused freeform passthrough

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

TOOL_NAME = "subdomain_takeover_check"
CATEGORY = "recon"

from _core.paths import container_or_local

_CLI = container_or_local(
    "/home/mcpuser/mcp-servers/recon/tools/_subdomain_takeover_cli.py",
    str(Path(__file__).resolve().with_name("_subdomain_takeover_cli.py")),
)


def build_command(**params: Any) -> str:
    target = str(
        params.get("target") or params.get("domain") or params.get("host") or ""
    ).strip()
    mode = str(params.get("mode") or "single").strip().lower() or "single"
    subdomains = str(params.get("subdomains") or params.get("input_data") or "").strip()
    max_hosts = int(params.get("max_hosts") or 50)

    if mode == "list" and not subdomains and not target:
        raise ValueError("subdomain_takeover_check mode=list needs subdomains= or target=")
    if mode != "list" and not target and not subdomains:
        raise ValueError("subdomain_takeover_check requires target= or subdomains=")

    payload: dict[str, Any] = {
        "target": target,
        "mode": mode,
        "subdomains": subdomains,
        "max_hosts": max_hosts,
    }
    encoded = json.dumps(payload, separators=(",", ":"))
    return f"python3 {shlex.quote(_CLI)} {shlex.quote(encoded)}"


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    target: str = "",
    mode: str = "single",
    subdomains: str = "",
    max_hosts: int = 50,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 180,
) -> dict[str, Any]:
    params = {
        "target": target,
        "mode": mode,
        "subdomains": subdomains,
        "max_hosts": max_hosts,
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
