"""
Execute Feroxbuster for recursive content discovery with enhanced logging.

Args:
    url: The target URL
    wordlist: Wordlist file to use
    threads: Number of threads
    additional_args: Additional Feroxbuster arguments

Returns:
    Content discovery results

Harvested: HexStrike `feroxbuster_scan` -> `/api/tools/feroxbuster`.
Category: web
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.command_utils import q
from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "feroxbuster_scan"
CATEGORY = "web"

# Bundled wordlist path inside the Kali container (mcp-servers is mounted here).
# Resolved at runtime in the shell (inside the Kali container): commands are
# built in the backend but executed via docker exec.
_WL_CONTAINER = "/home/mcpuser/mcp-servers/recon/tools/_wordlists/common-web.txt"
_WL_FALLBACK = str(
    Path(__file__).resolve().parents[2] / "recon" / "tools" / "_wordlists" / "common-web.txt"
)

def _wordlist_expr() -> str:
    return (
        f"$( [ -f {_WL_CONTAINER} ] && echo {_WL_CONTAINER} "
        f"|| echo {_WL_FALLBACK} )"
    )

def build_command(**params: Any) -> str:
    """Build a feroxbuster content-discovery command.

    Emits NDJSON (``--json``) so the parser gets status/size/url per hit, runs
    stateless (``--no-state`` — the resume-state file otherwise accumulates in
    the container and can wedge re-runs), and auto-filters wildcard/soft-404
    responses (``--auto-tune`` + ``--filter-status 404``). Recursion is bounded
    by default so a single call cannot fan out forever; raise it via
    ``additional_args`` (e.g. ``-d 3 -x php,txt,bak``).
    """
    url = str(params.get("url") or params.get("target") or "").strip()
    # Ship our own wordlist (the Kali image has none at /usr/share/wordlists);
    # the mcp-servers tree is mounted into the container at this path.
    wordlist_param = str(params.get("wordlist") or "").strip()
    wordlist = q(wordlist_param) if wordlist_param else _wordlist_expr()
    threads = int(params.get("threads") or 40)
    depth = int(params.get("depth") or 1)
    additional_args = str(params.get("additional_args") or "").strip()
    if not url:
        raise ValueError("feroxbuster_scan requires url=")

    parts = [
        "feroxbuster",
        f"-u {q(url)}",
        f"-w {wordlist}",
        f"-t {threads}",
        f"-d {depth}",
        "-k",  # skip TLS verification (targets with expired/self-signed certs)
        "--no-state",
        "--auto-tune",
        "--filter-status 404",
        "--json",
        "--silent",
    ]
    if additional_args:
        parts.append(additional_args)
    return " ".join(parts)

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', wordlist: str = '', threads: int = 10, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "wordlist": wordlist, "threads": threads, "additional_args": additional_args}
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
