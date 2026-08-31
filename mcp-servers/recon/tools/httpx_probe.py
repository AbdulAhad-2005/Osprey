"""
Execute HTTPx for HTTP probing with enhanced logging.

Args:
    targets: Target URLs or IPs
    target_file: File containing targets
    ports: Ports to probe
    methods: HTTP methods to use
    status_code: Filter by status code
    content_length: Show content length
    output_file: Output file path
    additional_args: Additional HTTPx arguments

Returns:
    HTTP probing results

Category: recon
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.command_utils import q
from _core.result import ToolResult
from _core.runner import default_parse, run_tool

TOOL_NAME = "httpx_probe"
CATEGORY = "recon"

_HTTPX_RESOLVER = r"""
HTTPX_BIN=""
for candidate in httpx-toolkit httpx-pd httpx; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -h 2>&1 | grep -q -- '-tech-detect'; then
    HTTPX_BIN="$(command -v "$candidate")"
    break
  fi
done
if [ -z "$HTTPX_BIN" ]; then
  echo "ProjectDiscovery httpx binary not found. Install it as httpx-toolkit/httpx-pd, or ensure the Go httpx binary is ahead of the Python httpx package CLI on PATH." >&2
  exit 127
fi
"""


def _httpx_command(argv: str) -> str:
    return "bash -lc " + q(f"{_HTTPX_RESOLVER}\n\"$HTTPX_BIN\" {argv}".strip())


def build_command(**params: Any) -> str:
    """Build CLI command."""
    # Accept the documented bulk-list aliases too — agents pass input_data= / host=
    # for many-host runs; only reading `target` silently dropped those lists.
    target = str(
        params.get("target")
        or params.get("input_data")
        or params.get("host")
        or params.get("url")
        or ""
    ).strip()
    probe = params.get("probe", True)
    tech_detect = params.get("tech_detect", False)
    status_code = params.get("status_code", False)
    content_length = params.get("content_length", False)
    title = params.get("title", False)
    web_server = params.get("web_server", False)
    threads = params.get("threads", 50)
    additional_args = params.get("additional_args", "")

    suffix = "-no-color -t " + str(threads)
    if probe:
        suffix += " -probe"
    if tech_detect:
        suffix += " -tech-detect"
    if status_code:
        suffix += " -sc"
    if content_length:
        suffix += " -cl"
    if title:
        suffix += " -title"
    if web_server:
        suffix += " -server"
    if additional_args:
        suffix += f" {additional_args}"

    lines = [line.strip() for line in target.replace(",", "\n").splitlines() if line.strip()]
    if not lines:
        raise ValueError("httpx_probe requires target")

    # -l expects a file path; -u accepts a single host/URL.
    if len(lines) == 1 and Path(lines[0]).is_file():
        return _httpx_command(f"-l {shlex.quote(lines[0])} {suffix}".strip())

    if len(lines) == 1:
        return _httpx_command(f"-u {shlex.quote(lines[0])} {suffix}".strip())

    # Multi-target: NEVER stuff 50+ hosts into `httpx -u a b c` (breaks ARG_MAX /
    # docker exec and caused backend 500s). Write a list file then `httpx -l`.
    import hashlib

    digest = hashlib.sha1("\n".join(lines).encode()).hexdigest()[:12]
    list_path = f"/tmp/httpx_targets_{digest}.txt"
    # printf is safer than echo for large lists; run under bash -c in Kali.
    payload = "\n".join(lines) + "\n"
    # Use python to write the file to avoid shell-escaping hundreds of hosts.
    write_py = (
        "python3 -c "
        + shlex.quote(
            "import pathlib; pathlib.Path(%r).write_text(%r, encoding='utf-8')"
            % (list_path, payload)
        )
    )
    return f"{write_py} && {_httpx_command(f'-l {shlex.quote(list_path)} {suffix}'.strip())}"

def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)

def run(target: str = '', probe: bool = True, tech_detect: bool = False, status_code: bool = False, content_length: bool = False, title: bool = False, web_server: bool = False, threads: int = 50, additional_args: str = '', use_recovery: bool = True, use_cache: bool = True, exec_timeout: int = 300) -> dict[str, Any]:
    params = {"target": target, "probe": probe, "tech_detect": tech_detect, "status_code": status_code, "content_length": content_length, "title": title, "web_server": web_server, "threads": threads, "additional_args": additional_args}
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
