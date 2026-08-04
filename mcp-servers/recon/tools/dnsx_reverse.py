"""
Reverse DNS (PTR) lookup with dnsx — map IPs back to hostnames at scale.

Given one or more IP addresses, query their PTR records to surface co-located
hostnames on shared infrastructure. Every hostname returned is a fresh recon
seed (virtual hosts, sibling services, forgotten names) that forward
subdomain enumeration never reaches.

Args:
    target: IP address(es) — newline/comma-separated, or a single IP.
    input_data / host / ip: bulk-list aliases for target.
    target_file: file containing IPs (one per line).
    threads: concurrent resolution threads.
    timeout: per-query timeout in seconds.
    additional_args: extra dnsx flags.

Returns:
    PTR hostnames per IP (reverse DNS), stored as new hostname seeds.

Reuses ProjectDiscovery dnsx (already bundled for dnsx_resolve) in -ptr mode.
Category: recon
"""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "dnsx_reverse"
CATEGORY = "recon"

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def build_command(**params: Any) -> str:
    """Build dnsx CLI command for reverse (PTR) resolution."""
    target = str(
        params.get("target")
        or params.get("input_data")
        or params.get("host")
        or params.get("ip")
        or ""
    ).strip()
    target_file = str(params.get("target_file", "")).strip()
    threads = params.get("threads", 50)
    timeout = params.get("timeout", 10)
    additional_args = str(params.get("additional_args", "")).strip()

    if not target and not target_file:
        raise ValueError("dnsx_reverse requires target (IP) or target_file")

    # -ptr asks dnsx for the reverse record; -resp prints the resolved hostname.
    cmd_parts = ["dnsx", "-silent", "-ptr", "-resp", "-no-color"]
    if threads:
        cmd_parts.append(f"-t {threads}")
    if timeout:
        cmd_parts.append(f"-timeout {timeout}")
    if additional_args:
        for aa in additional_args.split():
            if aa not in cmd_parts:
                cmd_parts.append(aa)

    if target_file and Path(target_file).is_file():
        cmd_parts.append(f"-l {shlex.quote(target_file)}")
        return " ".join(cmd_parts)

    lines = [line.strip() for line in target.replace(",", "\n").splitlines() if line.strip()]
    if not lines:
        raise ValueError("dnsx_reverse requires target (IP) or target_file")

    quoted_input = " ".join(shlex.quote(l) for l in lines)
    cmd = " ".join(cmd_parts)
    # Wrap in bash -c so the stdin pipe works (executor uses shell=False).
    return f"bash -c \"printf '%s\\n' {quoted_input} | {cmd}\""


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse dnsx -ptr output (``ip [PTR] [hostname]``) into ip→hostname pairs."""
    stdout = _ANSI_RE.sub("", result.raw_stdout or "")
    pairs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        ip, rest = line.split(" ", 1)
        ip = ip.strip()
        if not _IP_RE.match(ip):
            continue
        for match in re.finditer(r"\[([^\]]*)\]", rest):
            val = match.group(1).strip().rstrip(".").lower()
            if not val or val.upper() == "PTR" or "." not in val:
                continue
            key = (ip, val)
            if key in seen:
                continue
            seen.add(key)
            pairs.append({"ip": ip, "hostname": val})
    return {"ptr_records": pairs, "count": len(pairs)}


def run(
    target: str = "",
    target_file: str = "",
    threads: int = 50,
    timeout: int = 10,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "target": target,
        "target_file": target_file,
        "threads": threads,
        "timeout": timeout,
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
