"""
GraphQL security scan via graphql-cop — WSTG API/GraphQL coverage.

Replaces the crude curl-based graphql_scanner: graphql-cop runs a battery of
GraphQL-specific checks (introspection exposed, field suggestions, query
batching / aliasing DoS, GET-based mutations, CSRF, deep recursion, POST-JSON)
and rates each. JSON output is parsed into vulnerability findings.

Args:
    url: GraphQL endpoint (e.g. https://host/graphql).
    additional_args: extra graphql-cop flags.

Returns:
    graphql-cop JSON on stdout (parsed by the backend).

Category: web
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "graphql_cop_scan"
CATEGORY = "web"


def build_command(**params: Any) -> str:
    url = str(params.get("url") or params.get("target") or params.get("endpoint") or "").strip()
    additional_args = str(params.get("additional_args", "") or "").strip()
    if not url:
        raise ValueError("graphql_cop_scan requires url= (GraphQL endpoint)")
    cmd = f"graphql-cop -t {shlex.quote(url)} -o json"
    if additional_args:
        cmd += f" {additional_args}"
    return cmd


def parse(result: ToolResult) -> dict[str, Any]:
    return {"raw": bool(result.raw_stdout)}


def run(
    url: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 240,
) -> dict[str, Any]:
    params = {"url": url, "additional_args": additional_args}
    return run_tool(
        TOOL_NAME, build_command(**params), params=params, timeout=exec_timeout,
        use_cache=use_cache, use_recovery=use_recovery, parse_fn=parse,
    )
