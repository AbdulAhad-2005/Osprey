"""
Fast port discovery via ProjectDiscovery naabu.

Args:
    target: IP, hostname, CIDR — or a comma/space-separated list (multi-host
        is written to a temp -l list file, so any number of hosts works)
    ports: Port list/range, or 'top-N' / 'top_1000' style (maps to -top-ports)
    rate: Packets per second
    top_ports: Optional top-ports count (e.g. 100, 1000) when ports empty
    additional_args: Extra naabu flags

Category: network
"""

from __future__ import annotations

import hashlib
import re
import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.result import ToolResult
from _core.runner import default_parse, run_tool

TOOL_NAME = "naabu_port_scan"
CATEGORY = "network"
_MAX_INLINE_PORT_EXPANSION = 5000


def _normalize_ports(ports: str) -> str:
    if not ports:
        return ""
    expanded: list[str] = []
    seen: set[int] = set()
    for token in re.split(r"[,\s]+", ports):
        token = token.strip()
        if not token:
            continue
        range_match = re.fullmatch(r"(\d{1,5})-(\d{1,5})", token)
        if range_match:
            start = int(range_match.group(1))
            end = int(range_match.group(2))
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {token}")
            if end - start > _MAX_INLINE_PORT_EXPANSION:
                raise ValueError(
                    f"Port range {token} is too wide for naabu_port_scan; "
                    "use top_ports or an approved full scan"
                )
            for port in range(start, end + 1):
                if port not in seen:
                    seen.add(port)
                    expanded.append(str(port))
            continue
        if not token.isdigit():
            raise ValueError(f"Invalid port value: {token}")
        port = int(token)
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port value: {token}")
        if port not in seen:
            seen.add(port)
            expanded.append(str(port))
    return ",".join(expanded)


def build_command(**params: Any) -> str:
    target = str(params.get("target") or params.get("host") or "").strip()
    if not target:
        raise ValueError("naabu_port_scan requires target=")

    ports = str(params.get("ports") or "").strip()
    rate = str(params.get("rate") or "1000").strip()
    top_ports = str(params.get("top_ports") or "").strip()
    additional_args = str(params.get("additional_args") or "").strip()

    # ports='top-1000' / 'top_100' / 'top 100' → top_ports (naabu CLI naming)
    top_match = re.fullmatch(r"(?i)top[-_ ]?(\d+)", ports)
    if top_match and not top_ports:
        top_ports = top_match.group(1)
        ports = ""
    elif ports:
        ports = _normalize_ports(ports)

    hosts = [p.strip() for p in re.split(r"[,\s]+", target) if p.strip()]
    if len(hosts) > 1:
        # naabu -host takes ONE host; a comma list must go through -l,
        # otherwise a multi-IP target silently scans nothing.
        digest = hashlib.md5(target.encode()).hexdigest()[:8]
        list_file = f"/tmp/naabu_{digest}.txt"
        parts = [
            "printf",
            "%s\\n",
            shlex.quote("\n".join(hosts)),
            ">",
            list_file,
            "&&",
            "naabu",
            "-l",
            list_file,
            "-silent",
            "-rate",
            shlex.quote(rate),
        ]
    else:
        parts = [
            "naabu",
            "-host",
            shlex.quote(hosts[0]),
            "-silent",
            "-rate",
            shlex.quote(rate),
        ]
    if ports:
        parts.extend(["-p", shlex.quote(ports)])
    elif top_ports:
        parts.extend(["-top-ports", shlex.quote(top_ports)])
    else:
        parts.extend(["-top-ports", "1000"])

    if additional_args:
        parts.append(additional_args)

    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    return default_parse(result)


def run(
    target: str = "",
    ports: str = "",
    rate: int = 1000,
    top_ports: str = "1000",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 300,
) -> dict[str, Any]:
    params = {
        "target": target,
        "ports": ports,
        "rate": rate,
        "top_ports": top_ports,
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
