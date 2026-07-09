"""
Analyze API schemas and identify potential security issues.

Args:
    schema_url: URL to the API schema (OpenAPI/Swagger/GraphQL)
    schema_type: Type of schema (openapi, swagger, graphql)

Returns:
    Schema analysis results with security issues and recommendations

Harvested: HexStrike `api_schema_analyzer` -> `/api/tools/api_schema_analyzer`.
Category: api
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

TOOL_NAME = "api_schema_analyzer"
CATEGORY = "api"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    schema_url = params.get("schema_url", "")
    schema_type = params.get("schema_type", "openapi")  # openapi, swagger, graphql
    command = f"curl -s '{schema_url}'"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(schema_url: str = '', schema_type: str = 'openapi', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"schema_url": schema_url, "schema_type": schema_type}
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
