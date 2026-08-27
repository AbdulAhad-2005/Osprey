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

# Keyless sources VALID in theHarvester 4.11.x. Names drift between releases —
# `bing`, `anubis`, `threatminer`, `sitedossier`, `urlscan` were removed/renamed
# and any unknown source makes theHarvester abort the whole run ("Invalid
# source"), so only ship names the installed version accepts. `sources=all` is
# still available to the caller for the full (partly keyed) set.
_DEFAULT_SOURCES = (
    "crtsh,hackertarget,rapiddns,certspotter,dnsdumpster,otx,"
    "duckduckgo,threatcrowd"
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
    """Email count from stdout (backend osint parser mints typed EMAIL findings)."""
    import json
    import re

    text = result.raw_stdout or ""
    emails: list[str] = []
    seen: set[str] = set()
    rx = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")

    def _add(addr: str) -> None:
        e = addr.strip().lower().strip("\"'<>")
        if e and "@" in e and e not in seen and not e.endswith((".png", ".jpg", ".gif")):
            seen.add(e)
            emails.append(e)

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("# EMAILJSON "):
            try:
                obj = json.loads(stripped[len("# EMAILJSON "):])
            except (json.JSONDecodeError, ValueError):
                obj = None
            if isinstance(obj, dict):
                for item in obj.get("emails") or []:
                    _add(str(item))
    try:
        obj = json.loads(text.strip())
        if isinstance(obj, dict):
            for item in obj.get("emails") or []:
                _add(str(item))
    except (json.JSONDecodeError, ValueError):
        pass
    for match in rx.findall(text):
        _add(match)
    return {
        "emails": emails,
        "email_count": len(emails),
        "lines": len([ln for ln in text.splitlines() if ln.strip()]),
        "timed_out": bool(result.timed_out),
        "returncode": result.returncode,
    }


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
