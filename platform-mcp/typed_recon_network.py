"""Register typed FastMCP tools for recon + network catalog entries.

Each tool calls the same backend execute API as platform_exec, with explicit
Python parameters so the LLM does not reverse-engineer params_json.
"""

from __future__ import annotations

from typing import Any, Callable

# Keep in sync with agent_arg_normalizer primary sets (recon + network only).
TYPED_RECON_NETWORK_TOOLS: tuple[str, ...] = (
    # recon
    "subfinder_scan",
    "amass_scan",
    "httpx_probe",
    "waybackurls_discovery",
    "hakrawler_crawl",
    "dnsenum_scan",
    "fierce_scan",
    "whois_lookup",
    "gau_discovery",
    "anew_data_processing",
    "domain_hunter",
    "dnsx_resolve",
    "tlsx_inspect",
    "crt_sh_query",
    "cdn_origin_probe",
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
    "netexec_scan",
    "smbmap_scan",
    "enum4linux_scan",
    "enum4linux_ng_advanced",
    "responder_credential_harvest",
    "rpcclient_enumeration",
    "arp_scan_discovery",
    "nbtscan_netbios",
    "autorecon_scan",
    "autorecon_comprehensive",
)

_TOOL_BLURBS: dict[str, str] = {
    "subfinder_scan": "Passive subdomain enumeration (pass domain= or target=).",
    "amass_scan": "Amass subdomain / intel enum (domain=).",
    "httpx_probe": "Probe live HTTP hosts (target= URL/host list).",
    "waybackurls_discovery": "Historical URLs from Wayback (domain=).",
    "hakrawler_crawl": "Crawl links from a URL (url= or target=).",
    "dnsenum_scan": "DNS enumeration (domain=).",
    "fierce_scan": "DNS brute / fierce (domain=).",
    "whois_lookup": "WHOIS lookup (domain=).",
    "gau_discovery": "GetAllUrls historical URLs (domain=).",
    "anew_data_processing": "Deduplicate line-based tool output (input_data=).",
    "domain_hunter": "Sister/affiliate root domains (domain=).",
    "dnsx_resolve": "Bulk DNS resolve to IPs/CNAMEs (target= host list).",
    "tlsx_inspect": "TLS cert / SAN inspection (target=).",
    "crt_sh_query": "Certificate Transparency via crt.sh (domain=).",
    "cdn_origin_probe": "Soft CDN/origin clues via dig+curl (domain=). Confirm before scanning edges.",
    "shodan_search": "Passive Shodan search (query= or domain= → hostname:). Needs SHODAN_API_KEY.",
    "shodan_host_info": "Passive Shodan host detail (ip=/target= IP). Needs SHODAN_API_KEY.",
    "subdomain_takeover_check": "Dangling CNAME / SaaS takeover fingerprints (target= or mode=list + subdomains=).",
    "nmap_syn_scan": "TCP connect port scan (target=).",
    "nmap_service_scan": "Nmap service/version scan (target=, ports=).",
    "nmap_custom_scan": "Custom nmap (target=, flags= required).",
    "rustscan_fast_scan": "Fast port discovery (target=).",
    "naabu_port_scan": "Naabu fast port discovery (target=, optional ports=/top_ports=).",
    "masscan_high_speed": "Masscan (target=, ports=).",
    "netexec_scan": "NetExec / CrackMapExec style enum (target=).",
    "smbmap_scan": "SMB share enum (target=).",
    "enum4linux_scan": "Enum4linux (target=).",
    "enum4linux_ng_advanced": "Enum4linux-ng (target=).",
    "responder_credential_harvest": "Responder (gated — lab only).",
    "rpcclient_enumeration": "rpcclient enum (target=).",
    "arp_scan_discovery": "ARP scan (target= CIDR/IP).",
    "nbtscan_netbios": "NetBIOS scan (target=).",
    "autorecon_scan": "AutoRecon (target=).",
    "autorecon_comprehensive": "AutoRecon comprehensive (target=).",
}


def _build_params(
    *,
    domain: str = "",
    target: str = "",
    host: str = "",
    url: str = "",
    ports: str = "",
    flags: str = "",
    input_data: str = "",
    additional_args: str = "",
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
    if flags.strip():
        params["flags"] = flags.strip()
    if input_data.strip():
        params["input_data"] = input_data.strip()
    if additional_args.strip():
        params["additional_args"] = additional_args.strip()
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
                input_data: str = "",
                additional_args: str = "",
                timeout_seconds: int = 300,
            ) -> str:
                params = _build_params(
                    domain=domain,
                    target=target,
                    host=host,
                    url=url,
                    ports=ports,
                    flags=flags,
                    input_data=input_data,
                    additional_args="",
                )
                return execute(
                    name,
                    params,
                    additional_args=additional_args,
                    timeout_seconds=timeout_seconds,
                )

            _tool.__name__ = name
            _tool.__doc__ = (
                f"{doc}\n\n"
                "Typed recon/network tool — prefer this over platform_exec JSON. "
                "Aliases: domain|target|host|url are accepted; backend remaps. "
                "Escape hatch: platform_shell / platform_script."
            )
            return _tool

        handler = _make(tool_name, blurb)
        mcp.tool(name=tool_name)(handler)
        count += 1
    return count
