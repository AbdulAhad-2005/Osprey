"""Execute Subfinder for passive subdomain enumeration with enhanced logging.

Args:
    domain: The target domain
    silent: Run in silent mode
    all_sources: Use all sources
    additional_args: Additional Subfinder arguments

Returns:
    Passive subdomain enumeration results

Category: recon
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import default_parse, run_tool
from _core.result import ToolResult
from _core.command_utils import q

TOOL_NAME = "subfinder_scan"
CATEGORY = "recon"

_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def _sanitize_subdomains(raw_lines: list[str]) -> list[str]:
    """Filter out encoding artifacts and invalid hostnames from subfinder output.

    Subfinder occasionally emits HTML-escaped strings (e.g. u003ewww.nmap.org
    where u003e is an un-decoded >) or other non-hostname junk from
    upstream cert-transparency sources.  This strips obvious encoding leaks and
    rejects anything that does not look like a real hostname.
    """
    cleaned: list[str] = []
    seen: set[str] = set()
    for line in raw_lines:
        sub = line.strip().lower()
        if not sub:
            continue
        # Strip common HTML-escape leaks at the start/end.
        sub = re.sub(r"^u[0-9a-f]{4}", "", sub)
        sub = re.sub(r"u[0-9a-f]{4}$", "", sub)
        # Strip leading/trailing dots and angle brackets.
        sub = sub.strip(".<>")
        if not sub or not _HOSTNAME_RE.match(sub):
            continue
        if sub not in seen:
            seen.add(sub)
            cleaned.append(sub)
    return cleaned


def build_command(**params: Any) -> str:
    """Build CLI command."""
    domain = params.get("domain", "")
    silent = params.get("silent", True)
    all_sources = params.get("all_sources", False)
    additional_args = params.get("additional_args", "")
    command = f"subfinder -d {q(domain)}"
    if silent:
        command += " -silent"
    if all_sources:
        command += " -all"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()


def parse(result: ToolResult) -> dict[str, Any]:
    stdout = result.raw_stdout or ""
    raw_lines = [l for l in stdout.splitlines() if l.strip()]
    valid = _sanitize_subdomains(raw_lines)
    filtered_count = len(raw_lines) - len(valid)
    return {
        "subdomains": valid,
        "total_found": len(valid),
        "filtered_artifacts": filtered_count,
        "note": default_parse(result).get("note", ""),
    }


def run(domain: str = '', silent: bool = True, all_sources: bool = False, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"domain": domain, "silent": silent, "all_sources": all_sources, "additional_args": additional_args}
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
