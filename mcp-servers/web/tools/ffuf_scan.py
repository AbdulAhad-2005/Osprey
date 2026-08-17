"""
Execute FFuf for web fuzzing with enhanced logging.

Args:
    url: The target URL
    wordlist: Wordlist file to use
    mode: Fuzzing mode (directory, vhost, parameter)
    match_codes: HTTP status codes to match
    additional_args: Additional FFuf arguments

Returns:
    Web fuzzing results

Harvested: HexStrike `ffuf_scan` -> `/api/tools/ffuf`.
Category: web
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

TOOL_NAME = "ffuf_scan"
CATEGORY = "web"

# Bundled wordlist (Kali image ships none); mcp-servers is mounted at this path.
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

def _base_and_host(url: str) -> tuple[str, str]:
    """Return (normalized base url without trailing slash, hostname)."""
    u = (url or "").strip()
    if not u:
        return "", ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    u = u.rstrip("/")
    host = u.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
    return u, host


def build_command(**params: Any) -> str:
    """Build a coherent ffuf command for ONE fuzzing mode.

    The harvested version emitted four conflicting ``-u`` flags in a single
    invocation (directory + vhost + parameter at once), which ffuf silently
    reduces to the last one — so it never fuzzed what the caller asked for.
    This builds exactly one well-formed command per mode and emits NDJSON so
    the parser gets url + status + length per hit (``-ac`` auto-calibrates away
    the wildcard/soft-404 noise that makes raw content discovery unusable).
    """
    url = str(params.get("url") or params.get("target") or "").strip()
    wordlist = params.get("wordlist") or _wordlist_expr()
    mode = str(params.get("mode") or "directory").lower()
    match_codes = str(params.get("match_codes") or "200,204,301,302,307,401,403,405")
    threads = int(params.get("threads") or 40)
    additional_args = str(params.get("additional_args") or "").strip()
    if not url:
        raise ValueError("ffuf_scan requires url= (target URL)")

    base, host = _base_and_host(url)
    if mode == "vhost":
        # Fuzz the Host header against the base IP/host; match by response
        # differences (-ac handles the baseline). FUZZ is the vhost label.
        fuzz_url = base
        mode_args = f'-H "Host: FUZZ.{host}"'
    elif mode in ("parameter", "param"):
        joiner = "&" if "?" in base else "?"
        fuzz_url = f"{base}{joiner}FUZZ=ffuftest"
        mode_args = ""
    else:  # directory / file content discovery
        fuzz_url = f"{base}/FUZZ"
        mode_args = ""

    # -ac auto-calibration, -json NDJSON to stdout, -noninteractive keeps the
    # output line-oriented, stderr carries the progress bar (dropped by 2>/dev/null).
    parts = [
        "ffuf",
        f"-u {fuzz_url}",
        f"-w {wordlist}",
        f"-mc {match_codes}",
        f"-t {threads}",
        "-ac",
        "-k",  # ignore TLS cert errors (expired/self-signed targets)
        "-noninteractive",
        "-json",
    ]
    if mode_args:
        parts.append(mode_args)
    if additional_args:
        parts.append(additional_args)
    return " ".join(parts) + " 2>/dev/null"

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(url: str = '', wordlist: str = '', mode: str = 'directory', match_codes: str = '200,204,301,302,307,401,403', additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"url": url, "wordlist": wordlist, "mode": mode, "match_codes": match_codes, "additional_args": additional_args}
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
