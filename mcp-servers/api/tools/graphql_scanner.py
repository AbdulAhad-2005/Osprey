"""
Advanced GraphQL security scanning and introspection.

Args:
    endpoint: GraphQL endpoint URL
    introspection: Test introspection queries
    query_depth: Maximum query depth to test
    test_mutations: Test mutation operations

Returns:
    GraphQL security scan results with vulnerability assessment

Harvested: HexStrike `graphql_scanner` -> `/api/tools/graphql_scanner`.
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

TOOL_NAME = "graphql_scanner"
CATEGORY = "api"

def build_command(**params: Any) -> str:
    """Build CLI command (harvested from HexStrike server route)."""
    endpoint = params.get("endpoint", "")
    introspection = params.get("introspection", True)
    query_depth = params.get("query_depth", 10)
    mutations = params.get("test_mutations", True)
    if introspection:
        command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{clean_query}\"}}' '{endpoint}'"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(endpoint: str = '', introspection: bool = True, query_depth: int = 10, test_mutations: bool = True, use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"endpoint": endpoint, "introspection": introspection, "query_depth": query_depth, "test_mutations": test_mutations}
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
