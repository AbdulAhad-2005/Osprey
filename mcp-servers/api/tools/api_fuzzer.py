"""
Advanced API endpoint fuzzing with intelligent parameter discovery.

Args:
    base_url: Base URL of the API
    endpoints: Comma-separated list of specific endpoints to test
    methods: HTTP methods to test (comma-separated)
    wordlist: Wordlist for endpoint discovery

Returns:
    API fuzzing results with endpoint discovery and vulnerability assessment

Harvested: HexStrike `api_fuzzer` -> `/api/tools/api_fuzzer`.
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

TOOL_NAME = "api_fuzzer"
CATEGORY = "api"

def build_command(**params: Any) -> str:
    base_url = params.get("base_url", "")
    endpoints = params.get("endpoints", "")
    methods = params.get("methods", "GET,POST,PUT,DELETE")
    wordlist = params.get("wordlist", "/usr/share/wordlists/api/api-endpoints.txt")
    if endpoints:
        parts: list[str] = []
        for endpoint in endpoints.split(","):
            endpoint = endpoint.strip()
            if not endpoint:
                continue
            for method in methods.split(","):
                method = method.strip()
                if not method:
                    continue
                test_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
                parts.append(
                    f"curl -s -X {method} -w '%{{http_code}}|%{{size_download}}' '{test_url}'"
                )
        if parts:
            return " && ".join(parts)
    return (
        f"ffuf -u {base_url}/FUZZ -w {wordlist} "
        "-mc 200,201,202,204,301,302,307,401,403,405 -t 50"
    )

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(base_url: str = '', endpoints: str = '', methods: str = 'GET,POST,PUT,DELETE', wordlist: str = '/usr/share/wordlists/api/api-endpoints.txt', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"base_url": base_url, "endpoints": endpoints, "methods": methods, "wordlist": wordlist}
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
