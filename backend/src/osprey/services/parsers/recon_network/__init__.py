"""Deterministic stdout parsers for recon/network tools.

Structural extraction only — see plans/harness/02-evidence-and-observation-layer.md.
A scanner's own verdict (nmap NSE vulners/vulns.lua, a subdomain-takeover
check, a Shodan CVE tag) becomes a ``SCANNER_SIGNAL`` observation carrying the
claim as a fact ("the scanner said X"), never a judged ``VULNERABILITY``
finding — `confidence_for` (Plan 03) decides what that signal earns.
"""


# This module was split into a package (see the submodules alongside this
# file). Everything is re-exported here so the original import surface
# ``from osprey.services.parsers.recon_network import parse_X`` is unchanged,
# and importing the package still runs the parser registration below.

from __future__ import annotations

from osprey.schemas.observation import Observation

from osprey.services.parsers.recon_network.subdomains import (
    parse_subfinder,
    parse_httpx,
    _looks_like_cloudflare,
    _domain_hunter_rows,
    _dh_row_from_dict,
    _domain_hunter_table_rows,
    parse_domain_hunter,
)
from osprey.services.parsers.recon_network.nmap_ports import (
    _severity_for_cvss,
    _nse_signal,
    _process_vulners_block,
    _process_vulns_lua_block,
    parse_nmap_text,
    parse_rustscan,
    parse_naabu,
    parse_autorecon,
)
from osprey.services.parsers.recon_network.osint import (
    parse_shodan_search,
    parse_shodan_host_info,
)
from osprey.services.parsers.recon_network.dns_infra import (
    parse_subdomain_takeover,
    parse_dnsx,
    parse_tlsx,
    parse_crtsh,
    parse_cdn_origin_probe,
)
from osprey.services.parsers.recon_network.web_tech import (
    parse_wappalyzer,
    parse_whatweb,
    parse_tech_stack,
    parse_wafw00f,
)
from osprey.services.parsers.recon_network.summary import (
    extract_compact_summary,
)
from osprey.services.parsers.recon_network.urls import (
    _is_junk_url,
    _extract_unique_urls,
    extract_url_list_digest,
    _parse_url_list,
    parse_gau,
    parse_waybackurls,
    parse_hakrawler,
)
from osprey.services.parsers.recon_network.whois_asn import (
    parse_whois,
    parse_dnsenum,
    _is_ptr_ip_placeholder,
    parse_dnsx_reverse,
    parse_asn_enum,
)


def _register_recon_network_parsers() -> None:
    from osprey.services.parsers.registry import (
        register_output_digester,
        register_output_parser,
    )

    subdomain_tools = ("subfinder_scan", "amass_scan", "fierce_scan")
    for tool in subdomain_tools:
        register_output_parser(tool, parse_subfinder)
        register_output_digester(tool, lambda stdout, _t=tool: extract_compact_summary(_t, stdout))

    register_output_parser("httpx_probe", parse_httpx)
    register_output_digester("httpx_probe", lambda stdout: extract_compact_summary("httpx_probe", stdout))

    register_output_parser("domain_hunter", parse_domain_hunter)
    register_output_digester("domain_hunter", lambda stdout: extract_compact_summary("domain_hunter", stdout))

    register_output_parser("dnsx_resolve", parse_dnsx)
    register_output_digester("dnsx_resolve", lambda stdout: extract_compact_summary("dnsx_resolve", stdout))
    register_output_parser("dnsx_reverse", parse_dnsx_reverse)
    register_output_digester("dnsx_reverse", lambda stdout: extract_compact_summary("dnsx_reverse", stdout))
    register_output_parser("asn_enum", parse_asn_enum)
    register_output_digester("asn_enum", lambda stdout: extract_compact_summary("asn_enum", stdout))
    register_output_parser("tlsx_inspect", parse_tlsx)
    register_output_digester("tlsx_inspect", lambda stdout: extract_compact_summary("tlsx_inspect", stdout))
    register_output_parser("crt_sh_query", parse_crtsh)
    register_output_digester("crt_sh_query", lambda stdout: extract_compact_summary("crt_sh_query", stdout))
    register_output_parser("cdn_origin_probe", parse_cdn_origin_probe)
    register_output_digester(
        "cdn_origin_probe", lambda stdout: extract_compact_summary("cdn_origin_probe", stdout)
    )
    # cdn_origin_ip / cloudflare_origin_ip removed (duplicate of cdn_origin_probe).
    register_output_parser("origin_ip_attribution", parse_cdn_origin_probe)
    register_output_digester(
        "origin_ip_attribution", lambda stdout: extract_compact_summary("cdn_origin_probe", stdout)
    )

    register_output_parser("shodan_search", parse_shodan_search)
    register_output_digester("shodan_search", lambda stdout: extract_compact_summary("shodan_search", stdout))
    register_output_parser("shodan_host_info", parse_shodan_host_info)
    register_output_digester(
        "shodan_host_info", lambda stdout: extract_compact_summary("shodan_host_info", stdout)
    )
    register_output_parser("subdomain_takeover_check", parse_subdomain_takeover)
    register_output_digester(
        "subdomain_takeover_check",
        lambda stdout: extract_compact_summary("subdomain_takeover_check", stdout),
    )

    nmap_tools = ("nmap_syn_scan", "nmap_service_scan", "nmap_custom_scan")
    for tool in nmap_tools:
        register_output_parser(tool, parse_nmap_text)
        register_output_digester(tool, lambda stdout, _t=tool: extract_compact_summary(_t, stdout))

    # AutoRecon: its tool wrapper folds per-service nmap output into stdout;
    # reuse the nmap parser to extract ports/services from the collected files.
    # (autorecon_comprehensive was a byte-for-byte duplicate of autorecon_scan,
    # removed — resolve_tool_name/_TOOL_ALIASES maps the old name forward.)
    register_output_parser("autorecon_scan", parse_autorecon)

    # masscan is NOT registered here — its console format ("Discovered open
    # port N/tcp on IP") does not match parse_rustscan's regex. It is handled
    # by parsers/network_enum.parse_masscan instead.
    register_output_parser("rustscan_fast_scan", parse_rustscan)
    register_output_digester(
        "rustscan_fast_scan",
        lambda stdout: extract_compact_summary("rustscan_fast_scan", stdout),
    )

    register_output_parser("whois_lookup", parse_whois)
    register_output_digester("whois_lookup", lambda stdout: extract_compact_summary("whois_lookup", stdout))
    register_output_parser("dnsenum_scan", parse_dnsenum)
    register_output_digester("dnsenum_scan", lambda stdout: extract_compact_summary("dnsenum_scan", stdout))

    register_output_parser("naabu_port_scan", parse_naabu)
    register_output_digester("naabu_port_scan", lambda stdout: extract_compact_summary("naabu_port_scan", stdout))

    register_output_parser("wappalyzer_scan", parse_wappalyzer)
    register_output_parser("whatweb_scan", parse_whatweb)
    register_output_parser("tech_stack_analyze", parse_tech_stack)
    register_output_parser("wafw00f_scan", parse_wafw00f)

    register_output_parser("gau_discovery", parse_gau)
    register_output_digester("gau_discovery", lambda stdout: extract_url_list_digest("gau_discovery", stdout))
    register_output_parser("waybackurls_discovery", parse_waybackurls)
    register_output_digester(
        "waybackurls_discovery", lambda stdout: extract_url_list_digest("waybackurls_discovery", stdout)
    )
    register_output_parser("hakrawler_crawl", parse_hakrawler)
    register_output_digester(
        "hakrawler_crawl", lambda stdout: extract_url_list_digest("hakrawler_crawl", stdout)
    )


_register_recon_network_parsers()


async def parse_tool_output(
    tool_name: str,
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    """Backward-compatible wrapper — delegates to global parser registry."""
    from osprey.services.parsers.registry import parse_tool_output as registry_parse

    return await registry_parse(
        tool_name,
        stdout,
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
    )


__all__ = [
    "parse_subfinder",
    "parse_httpx",
    "_looks_like_cloudflare",
    "_domain_hunter_rows",
    "_dh_row_from_dict",
    "_domain_hunter_table_rows",
    "parse_domain_hunter",
    "_severity_for_cvss",
    "_nse_signal",
    "_process_vulners_block",
    "_process_vulns_lua_block",
    "parse_nmap_text",
    "parse_rustscan",
    "parse_naabu",
    "parse_autorecon",
    "parse_shodan_search",
    "parse_shodan_host_info",
    "parse_subdomain_takeover",
    "parse_dnsx",
    "parse_tlsx",
    "parse_crtsh",
    "parse_cdn_origin_probe",
    "parse_wappalyzer",
    "parse_whatweb",
    "parse_tech_stack",
    "parse_wafw00f",
    "extract_compact_summary",
    "_is_junk_url",
    "_extract_unique_urls",
    "extract_url_list_digest",
    "_parse_url_list",
    "parse_gau",
    "parse_waybackurls",
    "parse_hakrawler",
    "parse_whois",
    "parse_dnsenum",
    "_is_ptr_ip_placeholder",
    "parse_dnsx_reverse",
    "parse_asn_enum",
    "parse_tool_output",
]
