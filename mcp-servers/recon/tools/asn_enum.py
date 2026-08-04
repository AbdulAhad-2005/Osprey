"""
ASN / netblock enumeration via public whois services (passive).

Two modes:
  * IP mode (target=/ip=): Team Cymru IP-to-ASN mapping — returns the ASN,
    announced BGP prefix, country, registry and AS name for an IP. Tells you
    who really owns the address and its netblock.
  * ASN mode (asn=AS13335 or asn=13335): RADb route-object listing — returns
    every prefix announced by that ASN. If the org runs its own ASN, each
    prefix is a candidate asset range to sweep.

Expands scope beyond the tested domain to the organisation's full IP footprint
(sibling services with no DNS name, other domains in the same netblock).

Args:
    target / ip: an IP address (IP mode).
    asn: an ASN, with or without the "AS" prefix (ASN mode). Takes precedence.
    additional_args: reserved / extra whois flags.

Returns:
    ASN, AS name, country, registry and BGP prefix(es).

Uses the standard `whois` client against whois.cymru.com / whois.radb.net.
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

TOOL_NAME = "asn_enum"
CATEGORY = "recon"

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _normalize_asn(raw: str) -> str:
    """'AS13335' / '13335' / 'as 13335' → 'AS13335' (empty if not an ASN)."""
    digits = re.sub(r"(?i)^as[\s]*", "", (raw or "").strip())
    digits = digits.strip()
    if digits.isdigit():
        return f"AS{digits}"
    return ""


def build_command(**params: Any) -> str:
    """Build a whois command for Team Cymru (IP) or RADb (ASN)."""
    asn = _normalize_asn(str(params.get("asn", "")))
    target = str(params.get("target") or params.get("ip") or params.get("host") or "").strip()

    # ASN given (or the "IP" is actually an ASN) → RADb prefix listing.
    if not asn and _normalize_asn(target):
        asn = _normalize_asn(target)

    if asn:
        # RADb lists all route objects whose origin is this ASN.
        query = f"-i origin {asn}"
        return f"whois -h whois.radb.net -- {shlex.quote(query)}"

    if not target:
        raise ValueError("asn_enum requires target (IP) or asn")

    # Team Cymru verbose IP-to-ASN. The leading space in the argument switches
    # Cymru's whois interface into verbose (pipe-delimited) single-record mode.
    return f"whois -h whois.cymru.com {shlex.quote(' -v ' + target)}"


def _parse_cymru(stdout: str) -> dict[str, Any]:
    """Team Cymru pipe-delimited output → asn/prefix/cc/registry/as_name rows."""
    rows: list[dict[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        cols = [c.strip() for c in line.split("|")]
        # Header row: "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
        if cols and cols[0].upper() == "AS":
            continue
        if len(cols) < 3 or not cols[0].isdigit():
            continue
        row = {
            "asn": f"AS{cols[0]}",
            "ip": cols[1] if len(cols) > 1 else "",
            "prefix": cols[2] if len(cols) > 2 else "",
            "country": cols[3] if len(cols) > 3 else "",
            "registry": cols[4] if len(cols) > 4 else "",
            "as_name": cols[6] if len(cols) > 6 else (cols[-1] if len(cols) > 3 else ""),
        }
        rows.append(row)
    return {"mode": "ip", "rows": rows, "count": len(rows)}


def _parse_radb(stdout: str) -> dict[str, Any]:
    """RADb route-object output → announced prefixes for an ASN."""
    prefixes: list[dict[str, str]] = []
    seen: set[str] = set()
    cur_route = ""
    cur_descr = ""
    cur_origin = ""

    def _flush() -> None:
        nonlocal cur_route, cur_descr, cur_origin
        if cur_route and cur_route not in seen:
            seen.add(cur_route)
            prefixes.append(
                {"prefix": cur_route, "descr": cur_descr, "asn": cur_origin}
            )
        cur_route = cur_descr = cur_origin = ""

    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            _flush()
            continue
        m = re.match(r"^(route6?|descr|origin):\s*(.+)$", stripped, re.IGNORECASE)
        if not m:
            continue
        key = m.group(1).lower()
        val = m.group(2).strip()
        if key in ("route", "route6"):
            # New object starts — flush the previous one.
            if cur_route:
                _flush()
            cur_route = val
        elif key == "descr" and not cur_descr:
            cur_descr = val
        elif key == "origin":
            cur_origin = _normalize_asn(val) or val
    _flush()
    return {"mode": "asn", "prefixes": prefixes, "count": len(prefixes)}


def parse(result: ToolResult) -> dict[str, Any]:
    stdout = result.raw_stdout or ""
    # RADb objects always contain "route:"/"route6:"; Cymru is pipe-delimited.
    if re.search(r"(?im)^route6?:", stdout):
        return _parse_radb(stdout)
    return _parse_cymru(stdout)


def run(
    target: str = "",
    ip: str = "",
    asn: str = "",
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 120,
) -> dict[str, Any]:
    params = {"target": target, "ip": ip, "asn": asn, "additional_args": additional_args}
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
