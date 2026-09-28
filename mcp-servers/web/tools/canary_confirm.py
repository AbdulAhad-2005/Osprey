"""
Deterministic reflected-payload confirmation: fetch a URL you've already
injected a unique token into, and report — as a fact the platform checked
itself, not a claim — whether that exact token reflects back in the
response body/headers, at what surrounding context. The grounding a
platform_file_finding(evidence_kind='reproduction') claim needs for a
reflected-XSS/SSTI/template-injection finding: cite THIS tool's own
observation and quote its `context` field.

Args:
    url: The URL to fetch (already containing your injected canary)
    canary: The exact token you injected — checked byte-for-byte
    method: HTTP method (default GET)
    headers_json: JSON object of request headers
    body: Request body (for non-GET/HEAD)
    timeout: Seconds before giving up (default 15)

Category: webapp
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

TOOL_NAME = "canary_confirm"
CATEGORY = "web"

_CLI_CONTAINER = "/home/mcpuser/mcp-servers/web/tools/_canary_confirm_cli.py"
_CLI_FALLBACK = str(Path(__file__).resolve().with_name("_canary_confirm_cli.py"))


def _cli_expr() -> str:
    return (
        f"$( [ -f {_CLI_CONTAINER} ] && echo {_CLI_CONTAINER} "
        f"|| echo {_CLI_FALLBACK} )"
    )


def build_command(**params: Any) -> str:
    url = str(params.get("url") or "").strip()
    canary = str(params.get("canary") or "").strip()
    if not url or not canary:
        raise ValueError("canary_confirm requires url= and canary=")

    headers_json = str(params.get("headers_json") or "").strip()
    if headers_json:
        try:
            json.loads(headers_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"headers_json must be valid JSON: {exc}") from exc

    args = [
        shlex.quote(url),
        shlex.quote(canary),
        shlex.quote(str(params.get("method") or "GET")),
        shlex.quote(headers_json),
        shlex.quote(str(params.get("body") or "")),
        shlex.quote(str(params.get("timeout") or "15")),
    ]
    return f"python3 {_cli_expr()} " + " ".join(args)


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "invalid_json", "raw": raw[:500]}


def run(
    url: str = "",
    canary: str = "",
    method: str = "GET",
    headers_json: str = "",
    body: str = "",
    timeout: int = 15,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = False,
    exec_timeout: int = 30,
) -> dict[str, Any]:
    params = {
        "url": url, "canary": canary, "method": method,
        "headers_json": headers_json, "body": body, "timeout": timeout,
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
