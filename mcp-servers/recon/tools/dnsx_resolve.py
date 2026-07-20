"""
Bulk DNS resolution with dnsx — extract A, AAAA, CNAME, NS, MX records at scale.

Args:
    targets: Hostnames or domains to resolve (newline-separated or single)
    target_file: File containing targets (one per line)
    record_types: DNS record types to query (default: a,aaaa,cname,ns,mx)
    resolvers: Custom resolvers file
    threads: Concurrent resolution threads
    timeout: Resolution timeout in seconds
    additional_args: Additional dnsx arguments

Returns:
    DNS records for each target with IP addresses, CNAMEs, and nameservers

Harvested: ProjectDiscovery dnsx for bulk DNS resolution.
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

from _core.runner import default_parse, run_tool
from _core.result import ToolResult

TOOL_NAME = "dnsx_resolve"
CATEGORY = "recon"

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _strip_ansi(text: str) -> str:
    """Strip ANSI escape sequences from text."""
    return _ANSI_RE.sub("", text)


def build_command(**params: Any) -> str:
    """Build dnsx CLI command for bulk DNS resolution."""
    target = str(params.get("target", "")).strip()
    target_file = str(params.get("target_file", "")).strip()
    record_types = str(params.get("record_types", "a,cname,ns,mx")).strip()
    resolvers = str(params.get("resolvers", "")).strip()
    threads = params.get("threads", 50)
    timeout = params.get("timeout", 10)
    additional_args = str(params.get("additional_args", "")).strip()

    if not target and not target_file:
        raise ValueError("dnsx_resolve requires target or target_file")

    cmd_parts = ["dnsx", "-silent", "-resp", "-no-color"]

    type_map = {
        "a": "-a", "aaaa": "-aaaa", "cname": "-cname",
        "ns": "-ns", "mx": "-mx", "soa": "-soa", "txt": "-txt",
    }
    for rt in record_types.split(","):
        rt = rt.strip().lower()
        if rt in type_map:
            flag = type_map[rt]
            if flag not in cmd_parts:
                cmd_parts.append(flag)

    if resolvers:
        cmd_parts.append(f"-r {shlex.quote(resolvers)}")

    if threads:
        cmd_parts.append(f"-t {threads}")

    if timeout:
        cmd_parts.append(f"-timeout {timeout}")

    if additional_args:
        additional_args_list = additional_args.split()
        for aa in additional_args_list:
            if aa not in cmd_parts:
                cmd_parts.append(aa)

    if target_file and Path(target_file).is_file():
        cmd_parts.append(f"-l {shlex.quote(target_file)}")
        return " ".join(cmd_parts)

    lines = [line.strip() for line in target.replace(",", "\n").splitlines() if line.strip()]
    if not lines:
        raise ValueError("dnsx_resolve requires target or target_file")

    quoted_input = " ".join(shlex.quote(l) for l in lines)
    cmd = " ".join(cmd_parts)
    # Wrap in bash -c so pipes/shell features work (executor uses shell=False)
    return f"bash -c \"printf '%s\\n' {quoted_input} | {cmd}\""


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse dnsx output into structured DNS records."""
    records_list = []
    stdout = result.raw_stdout or ""
    stdout = _strip_ansi(stdout)

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Format: host [TYPE] [value]  or  host [value]
        # Split on first space to get host, then parse brackets
        space_idx = line.find(" ")
        if space_idx == -1:
            continue
        host = line[:space_idx].strip().lower()
        rest = line[space_idx + 1:].strip()

        values = []
        for match in re.finditer(r"\[([^\]]*)\]", rest):
            val = match.group(1).strip()
            if val and val.upper() not in ("A", "AAAA", "CNAME", "NS", "MX", "SOA", "TXT"):
                values.append(val)

        for value in values:
            records_list.append({"hostname": host, "value": value})

    hosts: dict[str, dict[str, list[str]]] = {}
    for rec in records_list:
        host = rec["hostname"]
        value = rec["value"]
        if host not in hosts:
            hosts[host] = {"ip": [], "cname": [], "ns": [], "mx": [], "other": []}

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            hosts[host]["ip"].append(value)
        elif value.count(".") >= 2:
            clean = value.rstrip(".")
            hosts[host]["cname"].append(clean)
        else:
            hosts[host]["other"].append(value)

    result_list = []
    for host, records in sorted(hosts.items()):
        result_list.append({
            "hostname": host,
            "records": {k: v for k, v in sorted(records.items()) if v},
        })

    return {"dns_records": result_list, "count": len(result_list)}


def run(
    target: str = "",
    target_file: str = "",
    record_types: str = "a,aaaa,cname,ns,mx",
    resolvers: str = "",
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
        "record_types": record_types,
        "resolvers": resolvers,
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
