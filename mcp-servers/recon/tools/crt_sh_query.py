"""
Certificate transparency log querying via crt.sh — discover subdomains and SANs.

Args:
    domain: Target domain to query CT logs for
    include_subdomains: Include subdomains in results (default: true)
    match_type: Match type (exact, wildcard, subdomains)
    timeout: HTTP request timeout in seconds
    additional_args: Additional curl arguments

Returns:
    Certificate entries from ct.sh including domains, SANs, issuer, and dates

Harvested: crt.sh Certificate Transparency API for passive subdomain discovery.
Category: recon
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from _core.runner import run_tool
from _core.result import ToolResult

TOOL_NAME = "crt_sh_query"
CATEGORY = "recon"

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"


def build_command(**params: Any) -> str:
    """Build curl command to query crt.sh API with built-in retry."""
    domain = str(params.get("domain", "")).strip()
    include_subdomains = params.get("include_subdomains", True)
    timeout = params.get("timeout", 45)
    additional_args = str(params.get("additional_args", "")).strip()

    if not domain:
        raise ValueError("crt_sh_query requires domain")

    if include_subdomains:
        query = f"%.{domain}"
    else:
        query = domain

    url = CRTSH_URL.format(domain=query)

    # curl --retry handles transient failures and 5xx from the public crt.sh
    # service (which is shared infrastructure and frequently returns 429/503).
    # --retry-connrefused: also retry when the connection is refused, not
    # just on HTTP error codes.
    parts = [
        "curl", "-s", "-sS",
        "--max-time", str(timeout),
        "--retry", "3",
        "--retry-delay", "5",
        "--retry-max-time", str(int(timeout) + 30),
        "--retry-connrefused",
    ]

    if additional_args:
        parts.append(additional_args)

    parts.append(shlex.quote(url))

    return " ".join(parts)


def parse(result: ToolResult) -> dict[str, Any]:
    """Parse crt.sh JSON output into structured certificate data."""
    findings = []
    stdout = result.raw_stdout or ""

    try:
        certs = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            "certificates": [],
            "count": 0,
            "error": "Invalid JSON response from crt.sh — the service may be overloaded or blocking. Retry later or use an alternative CT log (Censys, Certspotter).",
        }

    if not isinstance(certs, list):
        return {"certificates": [], "count": 0, "error": "Unexpected response format"}

    seen_domains: set[str] = set()
    for cert in certs:
        name_value = cert.get("name_value", "")
        issuer = cert.get("issuer_name", "")
        not_before = cert.get("not_before", "")
        not_after = cert.get("not_after", "")
        serial = cert.get("serial_number", "")

        domains = []
        for line in name_value.splitlines():
            domain = line.strip().lower()
            if domain and domain not in seen_domains:
                seen_domains.add(domain)
                domains.append(domain)

        if domains:
            findings.append({
                "domains": domains,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "serial": serial,
            })

    return {"certificates": findings, "count": len(findings), "unique_domains": len(seen_domains)}


def run(
    domain: str = "",
    include_subdomains: bool = True,
    match_type: str = "subdomains",
    timeout: int = 45,
    additional_args: str = "",
    use_recovery: bool = True,
    use_cache: bool = True,
    exec_timeout: int = 120,
) -> dict[str, Any]:
    params = {
        "domain": domain,
        "include_subdomains": include_subdomains,
        "match_type": match_type,
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
