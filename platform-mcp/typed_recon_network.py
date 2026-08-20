"""Register typed FastMCP tools for recon + network catalog entries.

Each tool calls the same backend execute API as platform_exec, with explicit
Python parameters so the LLM does not reverse-engineer params_json.
"""

from __future__ import annotations

import re
from typing import Any, Callable

# Keep in sync with agent_arg_normalizer primary sets (recon + network only).
#
# This is the EXTERNAL-recon toolbelt the Commander sees by default. Internal/AD
# tools (enum4linux, smbmap, netexec, rpcclient, nbtscan, arp_scan, responder) and
# low-value/heavy or redundant tools (autorecon*, fierce) are intentionally NOT
# typed here — they cannot work against remote/internet targets and only wasted
# turns in the default toolbelt. They remain fully executable via platform_exec
# (backend registry + parsers unchanged) for genuine internal engagements, and
# tech_dispatch still names them when a signal (e.g. port 445 open) warrants.
TYPED_RECON_NETWORK_TOOLS: tuple[str, ...] = (
    # recon
    "subfinder_scan",
    "amass_scan",
    "httpx_probe",
    "waybackurls_discovery",
    "hakrawler_crawl",
    "dnsenum_scan",
    "whois_lookup",
    "gau_discovery",
    "anew_data_processing",
    "domain_hunter",
    "dnsx_resolve",
    "dnsx_reverse",
    "asn_enum",
    "tlsx_inspect",
    "crt_sh_query",
    "cdn_origin_probe",
    "origin_ip_attribution",
    "shodan_search",
    "shodan_host_info",
    "subdomain_takeover_check",
    # network
    "nmap_syn_scan",
    "nmap_service_scan",
    "nmap_custom_scan",
    "rustscan_fast_scan",
    "naabu_port_scan",
    "masscan_high_speed",
)

_TOOL_BLURBS: dict[str, str] = {
    "subfinder_scan": "Passive subdomain enumeration (pass domain= or target=).",
    "amass_scan": "Amass subdomain / intel enum (domain=). SLOW: 5-15+ min with default sources — start it via platform_job_start and continue other work; subfinder_scan already covers most names faster.",
    "httpx_probe": "Probe live HTTP hosts (target= URL/host list).",
    "waybackurls_discovery": "Historical URLs from Wayback (domain=).",
    "hakrawler_crawl": "Crawl links from a URL (url= or target=).",
    "dnsenum_scan": "DNS enumeration (domain=).",
    "fierce_scan": "DNS brute / fierce (domain=).",
    "whois_lookup": "WHOIS lookup (domain=). Auto-strips subdomains to apex domain.",
    "gau_discovery": "GetAllUrls historical URLs (domain=).",
    "anew_data_processing": "Deduplicate line-based tool output (input_data=).",
    "domain_hunter": "Sister/affiliate root domains (domain=).",
    "dnsx_resolve": "Bulk DNS resolve to IPs/CNAMEs (target= host list).",
    "dnsx_reverse": "Reverse DNS / PTR (target= IP list) — maps IPs back to hostnames; each PTR name is a new seed. Run on resolved IPs to find co-located vhosts.",
    "asn_enum": "ASN/netblock enum (target= IP → Team Cymru IP→ASN, or target=AS#### → RADb prefix list). Expands scope to the org's full IP range. Skip provider-owned cloud ranges.",
    "tlsx_inspect": "TLS cert / SAN inspection (target=).",
    "crt_sh_query": "Certificate Transparency via crt.sh (domain=). SLOW: crt.sh queries routinely take 30-120s (retries on timeout) — use platform_job_start for it in parallel with other recon.",
    "cdn_origin_probe": "Soft CDN/origin clues via dig+curl (domain=). Confirm before scanning edges.",
    "shodan_search": "Passive Shodan search (query= or domain= → hostname:). Needs SHODAN_API_KEY.",
    "shodan_host_info": "Passive Shodan host detail (ip=/target= IP). Needs SHODAN_API_KEY.",
    "subdomain_takeover_check": "Dangling CNAME / SaaS takeover fingerprints (target= or mode=list + subdomains=).",
    "origin_ip_attribution": "Full origin IP attribution pipeline — DNS, TLS, headers, CIDR classification, verification (domain=). The deep option; cdn_origin_probe is the fast one.",
    "nmap_syn_scan": "TCP SYN scan (-sS, target=). Always runs privileged (root in the Kali container) — a real SYN scan, not a connect-scan fallback.",
    "nmap_service_scan": "Nmap service/version scan (-sV -sC, target=, ports=). host_timeout= overrides the per-host NSE budget (scales automatically for wide/full port ranges; 'none' removes it entirely).",
    "nmap_custom_scan": "Custom nmap (target=, flags= required). Always runs privileged (real root in the Kali container) — -sS/-O/any raw-socket flag just works, no privileged= param needed. host_timeout= overrides the per-host NSE budget (auto-scales for -p-/wide ranges already; 'none' removes it entirely). For a full-range scan across many hosts, use platform_job_start — this call's own foreground ceiling is much shorter than nmap itself may need.",
    "rustscan_fast_scan": "Fast port discovery (target=).",
    "naabu_port_scan": "Naabu fast port discovery. target= accepts ONE host, a comma-separated IP list (multi-host auto-written to a temp -l list), or a CIDR. ports= accepts a list/range OR 'top-N' (e.g. ports='top-1000'); top_ports=N also works. Default: top-ports 1000.",
    "masscan_high_speed": "Masscan (target=, ports=).",
}


# Per-tool default foreground timeouts (seconds) for the slow recon tools —
# these routinely exceed a flat 300s (archive crawls, DNS brute, OSINT hunts),
# forcing needless background re-runs. 0 from the caller uses this default; an
# explicit timeout_seconds still overrides.
_SLOW_TIMEOUTS: dict[str, int] = {
    "domain_hunter": 600,
    "dnsenum_scan": 600,
    "gau_discovery": 480,
    "waybackurls_discovery": 480,
    "hakrawler_crawl": 480,
    "amass_scan": 600,
}
_DEFAULT_NET_TIMEOUT = 300


def _normalize_ports_value(ports: str) -> tuple[str, str]:
    """Split a raw ports= string into structured (ports, top_ports) values.

    Strips a mistaken -p/--ports prefix the LLM may include. 'top-N' /
    'top_N' / 'top N' shorthand is classified into top_ports rather than
    ports. This ONLY cleans and classifies the raw value — it never renders
    a CLI flag. Each tool's own build_command() renders its own correct flag
    from these structured values (naabu: -top-ports N; nmap family:
    --top-ports N; ports lists become that tool's own -p/--ports flag) —
    that per-tool rendering is why pre-rendering a flag string here and
    folding it into additional_args caused duplicate/invalid flags whenever
    a tool's own builder also emitted a ports flag from the same params.
    Returns ('', '') when ports is empty.
    """
    cleaned = (ports or "").strip()
    if not cleaned:
        return "", ""
    cleaned = re.sub(r"^--?p(?:orts?)?\s*", "", cleaned, flags=re.I).strip()
    if not cleaned:
        return "", ""
    top_match = re.fullmatch(r"(?i)top[-_ ]?(\d+)", cleaned)
    if top_match:
        return "", top_match.group(1)
    return cleaned, ""


def _build_params(
    *,
    domain: str = "",
    target: str = "",
    host: str = "",
    url: str = "",
    ports: str = "",
    top_ports: str = "",
    flags: str = "",
    mode: str = "",
    subdomains: str = "",
    input_data: str = "",
    additional_args: str = "",
    confirm_expensive: str = "",
    privileged: bool = False,
    host_timeout: str = "",
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if domain.strip():
        params["domain"] = domain.strip()
    if target.strip():
        params["target"] = target.strip()
    if host.strip():
        params["host"] = host.strip()
    if url.strip():
        params["url"] = url.strip()
    if ports.strip():
        params["ports"] = ports.strip()
    if top_ports.strip():
        params["top_ports"] = top_ports.strip()
    if flags.strip():
        params["flags"] = flags.strip()
    if mode.strip():
        params["mode"] = mode.strip()
    if subdomains.strip():
        params["subdomains"] = subdomains.strip()
    if input_data.strip():
        params["input_data"] = input_data.strip()
    if additional_args.strip():
        params["additional_args"] = additional_args.strip()
    if confirm_expensive.strip():
        params["confirm_expensive"] = confirm_expensive.strip()
    if privileged:
        params["privileged"] = "true"
    if host_timeout.strip():
        params["host_timeout"] = host_timeout.strip()
    return params


def register_typed_recon_network_tools(
    mcp: Any,
    *,
    execute: Callable[..., str],
) -> int:
    """
    Register one FastMCP tool per recon/network catalog name.

    ``execute(tool_name, params, additional_args, timeout_seconds) -> str``
    must bind engagement and POST /api/v1/mcp/execute (same as platform_exec).
    """
    count = 0
    for tool_name in TYPED_RECON_NETWORK_TOOLS:
        blurb = _TOOL_BLURBS.get(tool_name, f"Catalog tool {tool_name}.")

        def _make(name: str, doc: str) -> Callable[..., str]:
            def _tool(
                domain: str = "",
                target: str = "",
                host: str = "",
                url: str = "",
                ports: str = "",
                flags: str = "",
                mode: str = "",
                subdomains: str = "",
                input_data: str = "",
                additional_args: str = "",
                confirm_expensive: str = "",
                privileged: bool = False,
                host_timeout: str = "",
                timeout_seconds: int = 0,
                engagement_id: str = "",
            ) -> str:
                ports_value, top_ports_value = _normalize_ports_value(ports)
                params = _build_params(
                    domain=domain,
                    target=target,
                    host=host,
                    url=url,
                    ports=ports_value,
                    top_ports=top_ports_value,
                    flags=flags,
                    mode=mode,
                    subdomains=subdomains,
                    input_data=input_data,
                    additional_args="",
                    confirm_expensive=confirm_expensive,
                    privileged=privileged,
                    host_timeout=host_timeout,
                )
                effective_timeout = timeout_seconds or _SLOW_TIMEOUTS.get(
                    name, _DEFAULT_NET_TIMEOUT
                )
                return execute(
                    name,
                    params,
                    additional_args=(additional_args or "").strip(),
                    timeout_seconds=effective_timeout,
                    engagement_id=engagement_id,
                )

            _tool.__name__ = name
            _tool.__doc__ = (
                f"{doc}\n\n"
                "Typed recon/network tool — prefer this over platform_exec JSON. "
                "Aliases: domain|target|host|url are accepted; backend remaps. "
                "engagement_id= pins this call to a specific engagement (the id "
                "platform_set_target returned) so it is not affected if another "
                "chat switches the ambient target; omit for the current session. "
                "Escape hatch: platform_shell / platform_script."
            )
            return _tool

        handler = _make(tool_name, blurb)
        mcp.tool(name=tool_name)(handler)
        count += 1
    return count
