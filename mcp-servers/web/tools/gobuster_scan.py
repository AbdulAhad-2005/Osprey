"""
Execute Gobuster to find directories, DNS subdomains, or virtual hosts with enhanced logging.

Args:
    url: The target URL
    mode: Scan mode (dir, dns, fuzz, vhost)
    wordlist: Path to wordlist file
    additional_args: Additional Gobuster arguments

Returns:
    Scan results with enhanced telemetry

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

TOOL_NAME = "gobuster_scan"
CATEGORY = "web"

# Bundled wordlists (Kali image ships none); mcp-servers is mounted at this path
# in Docker mode. Resolved by NAME, not by a caller-supplied filesystem path, so
# no caller (config, engine, LLM) ever needs to know the container-vs-host split —
# `$( [ -f <container> ] && ... || ... )` is evaluated by the shell that actually
# runs the command (bash -c, both in docker-exec and native execution), so it
# picks whichever path is real wherever this command ends up running.
_BUNDLED_WORDLISTS = {
    "common-web": "common-web.txt",
    "subdomains": "subdomains.txt",
}
_WL_LOCAL_DIR = Path(__file__).resolve().parents[2] / "recon" / "tools" / "_wordlists"


def _bundled_wordlist_expr(filename: str) -> str:
    container = f"/home/mcpuser/mcp-servers/recon/tools/_wordlists/{filename}"
    fallback = str(_WL_LOCAL_DIR / filename)
    return f"$( [ -f {container} ] && echo {container} || echo {fallback} )"


def build_command(**params: Any) -> str:
    """Build CLI command."""
    url = str(params.get("url") or params.get("target") or "").strip()
    mode = str(params.get("mode") or "dir").strip()
    wordlist_param = str(params.get("wordlist") or "").strip()
    if not wordlist_param:
        wordlist = _bundled_wordlist_expr(_BUNDLED_WORDLISTS["common-web"])
    elif wordlist_param in _BUNDLED_WORDLISTS:
        wordlist = _bundled_wordlist_expr(_BUNDLED_WORDLISTS[wordlist_param])
    else:
        # A caller-supplied literal path (bring-your-own-wordlist) — used as-is.
        wordlist = q(wordlist_param)
    additional_args = str(params.get("additional_args") or "").strip()
    if not url:
        raise ValueError("gobuster_scan requires url=")
    # dns mode uses --domain (the -d short flag is --delay in gobuster >= 3.6)
    # not -u; dir/vhost use -u and can skip TLS verify. dns mode needs a BARE
    # domain: the engine's frontier labels can carry a scheme (https://…), and
    # `gobuster dns --domain https://x` silently brute-forces garbage and
    # returns zero hits. Normalize at the tool boundary so every caller gets
    # the same correct behavior.
    if mode == "dns":
        domain = url.split("://", 1)[1] if "://" in url else url
        domain = domain.split("/", 1)[0].strip().rstrip(".")
        if not domain:
            raise ValueError("gobuster_scan dns mode requires a bare domain (no scheme/path)")
        command = f"gobuster dns --domain {q(domain)} -w {wordlist}"
    else:
        command = f"gobuster {q(mode)} -u {q(url)} -w {wordlist} -k"
    if additional_args:
        command += f" {additional_args}"
    return command.strip()

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', mode: str = 'dir', wordlist: str = '', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "mode": mode, "wordlist": wordlist, "additional_args": additional_args}
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
