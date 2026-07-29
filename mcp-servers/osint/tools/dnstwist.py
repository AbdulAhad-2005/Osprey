"""
dnstwist — generate and resolve typosquat / look-alike permutations of a domain
to surface phishing, brand-abuse and impersonation infrastructure. Keyless.

Args:
    domain: Seed domain (e.g. example.com)
    target: Alias for domain
    registered_only: Only report permutations that actually resolve (default true)
    additional_args: Extra dnstwist flags (any)

Category: osint

Passive: only DNS/whois lookups on generated names — never touches the seed host.
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

TOOL_NAME = "dnstwist"
CATEGORY = "osint"


def build_command(**params: Any) -> str:
    domain = str(params.get("domain") or params.get("target") or "").strip()
    registered_only = params.get("registered_only", True)
    additional_args = str(params.get("additional_args") or "").strip()

    if not domain:
        raise ValueError("dnstwist requires domain= (or target=)")

    parts = ["dnstwist", "--format", "json"]
    if registered_only in (True, "true", "1", 1):
        parts.append("--registered")
    if additional_args:
        parts.append(additional_args)
    parts.append(shlex.quote(domain))
    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    raw = (result.raw_stdout or "").strip()
    try:
        data = json.loads(raw)
        return {"permutations": len(data) if isinstance(data, list) else 0}
    except (json.JSONDecodeError, ValueError):
        return {"permutations": 0, "error": "invalid_json"}


def run(
    domain: str = "",
    target: str = "",
    registered_only: bool = True,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 240,
) -> dict[str, Any]:
    params = {
        "domain": domain,
        "target": target,
        "registered_only": registered_only,
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
