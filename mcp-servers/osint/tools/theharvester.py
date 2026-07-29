"""
theHarvester — passive harvest of emails, names, subdomains, hosts and IPs for a
domain from public search engines and OSINT sources (keyless sources by default).

Args:
    domain: Target domain / company domain to harvest (e.g. example.com)
    target: Alias for domain when the LLM passes target=
    sources: Comma-separated source list (default: keyless engines). Use "all" to
             include keyed sources (they warn + skip when no key is set).
    limit: Max results per source (default 200)
    additional_args: Extra theHarvester flags (any)

Category: osint

theHarvester is passive: it only queries public indexes, never touches the target.
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

TOOL_NAME = "theharvester"
CATEGORY = "osint"

# Sources that work without an API key. "all" is available via sources=all.
_DEFAULT_SOURCES = (
    "crtsh,duckduckgo,bing,otx,hackertarget,rapiddns,anubis,"
    "threatminer,urlscan,certspotter,dnsdumpster,sitedossier"
)


def build_command(**params: Any) -> str:
    domain = str(params.get("domain") or params.get("target") or "").strip()
    sources = str(params.get("sources") or _DEFAULT_SOURCES).strip()
    limit = str(params.get("limit") or 200).strip()
    additional_args = str(params.get("additional_args") or "").strip()

    if not domain:
        raise ValueError("theharvester requires domain= (or target=)")

    parts = [
        "theHarvester",
        "-d", shlex.quote(domain),
        "-b", shlex.quote(sources),
        "-l", shlex.quote(limit),
    ]
    if additional_args:
        parts.append(additional_args)
    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    """Light stub — the backend osint parser turns stdout into typed findings."""
    text = result.raw_stdout or ""
    return {"lines": len([ln for ln in text.splitlines() if ln.strip()])}


def run(
    domain: str = "",
    target: str = "",
    sources: str = "",
    limit: int = 200,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "domain": domain,
        "target": target,
        "sources": sources,
        "limit": limit,
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
