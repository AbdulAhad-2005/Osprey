"""Fast scan — deterministic, no LLM, no sister-domain expansion.

whois -> direct subdomain enumeration -> TLS-SAN discovery (merged into the
host set) -> resolve every host to IPs + CNAMEs -> classify CDN-edge vs
origin IPs -> TLS-SAN pass on origin IPs too (a CDN-fronted apex's cert
isn't the origin's) -> httpx live-probe -> nmap on origin IPs (fast
rate-boosted SYN sweep for open ports, then -sV -sC -O against just those
ports with no forced rate — a single min-rate'd pass starves version/OS
probes of proper timing and produces "tcpwrapped"/garbage OS guesses), a
light 80/443 check on CDN-fronted IPs -> dangling-CNAME takeover check.
Narrow and fast by design: no domain_hunter/sister-domain discovery, no
crawling/fuzzing, no full vuln scanning — every step here is passive/direct
against the target's own DNS, TLS, and IP surface. For the full BFS breadth
engine (sisters, tech/CDN, vuln), use JobKind.EXPANSION (surface_expansion.py)
instead.
"""

from __future__ import annotations

import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.tools import ToolExecutionRequest
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.tool_execution import execute_tool_request

logger = logging.getLogger(__name__)

_MCP_SERVERS_DIR = Path(__file__).resolve().parents[4] / "mcp-servers"


def _classify_ips_by_cdn(ip_list: list[str]) -> dict[str, str | None]:
    """Classify each IP against published CDN CIDR ranges.

    Reuses origin_ip_attribution's own `_classify_ip` — a pure CIDR lookup,
    no network I/O — instead of routing every host through that tool's full
    multi-target DNS+HTTP probe loop (correct, but far too slow to run once
    per discovered host in a "fast" scan; mcp_client.py's _parse_tool_output
    already dynamically loads mcp-servers tool modules from the backend the
    same way, so this follows the established pattern).
    """
    mcp_str = str(_MCP_SERVERS_DIR)
    if mcp_str not in sys.path:
        sys.path.insert(0, mcp_str)
    from recon.tools.origin_ip_attribution import _classify_ip

    return {ip: _classify_ip(ip) for ip in ip_list}

# Stays under scan_budget's confirm-required thresholds (--top-ports is always
# allowed; nmap's no-confirm port cap is 2000) while still covering the vast
# majority of commonly-open ports — "fast" and "sees all major ports", not a
# full 1-65535 sweep (that's a deliberate, separate, confirm_expensive action).
_NMAP_TOP_PORTS = 2000
_NMAP_MIN_RATE = 1000
# Origin IPs get TWO passes, not one. --min-rate forces a packet-rate floor
# across nmap's ENTIRE probe stream, not just SYN discovery — combined with
# -sV/-O in a single invocation it starves version/OS probes of the round
# trips they need, and the target's own rate-limiting drops the burst. That
# produces exactly "tcpwrapped" ports and garbage OS guesses (a switch/phone
# fingerprint on a Windows box) — nmap ran, but its actual deliverable is
# wrong. Pass 1 is a fast, rate-boosted SYN sweep to find open ports; pass 2
# runs -sV -sC -O against only those ports, no forced rate, so the probes
# get proper timing. Real-world pentest methodology, not a platform quirk.
_NMAP_DISCOVERY_FLAGS = f"-sS -Pn --top-ports {_NMAP_TOP_PORTS} --min-rate {_NMAP_MIN_RATE} -T4"
_NMAP_SERVICE_FLAGS_TMPL = "-sV -sC -O -Pn -p {ports} --max-retries 2 -T3"
# CDN-fronted IPs: deep-scanning the edge just measures the CDN, not the
# target — a cheap 80/443 touch is enough to record what the edge serves.
# Already narrow with no forced rate, so it isn't subject to the same issue.
_NMAP_LIGHT_FLAGS = "-sV -Pn -p 80,443"

_CNAME_RE = re.compile(r"^(\S+)\s+CNAME\s*->\s*(\S+)$")
# Matches nmap finding titles from parse_nmap_text: f"{host}:{port}/{proto} {svc}"
_OPEN_PORT_TITLE_RE = re.compile(r":(\d+)/(?:tcp|udp)\s")


def _extract_open_ports(finding_titles: list[str]) -> list[str]:
    """Pull port numbers out of nmap finding titles, in first-seen order."""
    ports: list[str] = []
    for title in finding_titles:
        m = _OPEN_PORT_TITLE_RE.search(title)
        if m and m.group(1) not in ports:
            ports.append(m.group(1))
    return ports


@dataclass
class NmapResult:
    ip: str
    success: bool
    scan_type: str = "full"
    finding_titles: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class FastScanReport:
    engagement_id: str
    target: str
    whois_ok: bool = False
    subdomains_found: int = 0
    sans_found: int = 0
    hosts_scanned: list[str] = field(default_factory=list)
    ips_resolved: int = 0
    ips: list[str] = field(default_factory=list)
    cdn_edge_ips: list[str] = field(default_factory=list)
    origin_ips: list[str] = field(default_factory=list)
    live_hosts: int = 0
    live_urls: list[str] = field(default_factory=list)
    cname_count: int = 0
    takeover_flags: list[str] = field(default_factory=list)
    nmap_results: list[NmapResult] = field(default_factory=list)
    stopped_reason: str = "completed"


async def _exec(
    tool_name: str,
    params: dict[str, Any],
    *,
    engagement_id: str,
    run_id: str,
    timeout: int = 300,
):
    return await execute_tool_request(
        ToolExecutionRequest(
            tool_name=tool_name,
            params=params,
            engagement_id=engagement_id,
            run_id=run_id or None,
            timeout=timeout,
            record_findings=True,
            use_recovery=True,
        )
    )


async def run_fast_scan(
    engagement_id: str,
    run_id: str,
    target: str,
    *,
    on_progress: Callable[[str], None] | None = None,
) -> FastScanReport:
    """Run the deterministic pipeline against ``target``."""
    report = FastScanReport(engagement_id=engagement_id, target=target)
    apex = target.strip().lower()
    graph = get_engagement_graph()

    def _progress(text: str) -> None:
        if on_progress is not None:
            on_progress(text)

    # 1) WHOIS
    _progress(f"whois: looking up registration data for {target}")
    whois_resp = await _exec(
        "whois_lookup", {"target": target}, engagement_id=engagement_id, run_id=run_id,
    )
    report.whois_ok = bool(whois_resp.success)
    _progress(f"RESULT::whois {target}: {'ok' if report.whois_ok else 'failed'}")

    # 2) Subdomain enumeration — direct only, no domain_hunter/sister discovery
    _progress(f"subfinder: enumerating subdomains of {target}")
    sub_resp = await _exec(
        "subfinder_scan", {"domain": target, "silent": True},
        engagement_id=engagement_id, run_id=run_id, timeout=180,
    )
    subdomains = sorted({t.strip().lower() for t in (sub_resp.finding_titles or []) if t.strip()})
    report.subdomains_found = len(subdomains)
    hosts = sorted({apex, *subdomains})

    # 3) TLS cert SAN pass — free subdomains DNS enumeration misses. Only
    # merge SANs that stay in-scope (same apex) — shared/multi-tenant certs
    # can list unrelated domains and this must not turn into sister discovery.
    _progress(f"tlsx: inspecting TLS certs on {len(hosts)} host(s) for SAN names")
    await _exec(
        "tlsx_inspect", {"target": "\n".join(hosts), "port": 443},
        engagement_id=engagement_id, run_id=run_id, timeout=120,
    )
    san_nodes = graph.list_nodes(
        engagement_id=engagement_id, asset_type=AssetType.SUBDOMAIN, run_id=run_id, limit=2000,
    )
    sans = {
        n.label.strip().lower()
        for n in san_nodes
        if n.source_tool == "tlsx_inspect" and n.label.strip()
    }
    sans = {s for s in sans if s == apex or s.endswith("." + apex)}
    new_sans = sorted(sans - set(hosts))
    report.sans_found = len(new_sans)
    hosts = sorted({*hosts, *sans})
    report.hosts_scanned = hosts
    _progress(
        f"RESULT::subfinder found {len(subdomains)} subdomain(s); "
        f"tlsx found {len(new_sans)} extra SAN host(s); {len(hosts)} host(s) total"
    )

    # 4) Resolve every host to IPs + CNAMEs
    _progress(f"dnsx: resolving {len(hosts)} host(s) to IPs and CNAMEs")
    dnsx_resp = await _exec(
        "dnsx_resolve", {"target": "\n".join(hosts), "record_types": "a,cname"},
        engagement_id=engagement_id, run_id=run_id, timeout=120,
    )
    cname_map: dict[str, str] = {}
    for line in dnsx_resp.finding_titles or []:
        m = _CNAME_RE.match(line.strip())
        if m:
            cname_map[m.group(1).lower()] = m.group(2).lower()
    report.cname_count = len(cname_map)
    ip_nodes = graph.list_nodes(
        engagement_id=engagement_id, asset_type=AssetType.IP, run_id=run_id, limit=2000,
    )
    ips = sorted({n.label.strip() for n in ip_nodes if n.label.strip()})
    report.ips_resolved = len(ips)
    report.ips = ips
    _progress(f"RESULT::dnsx resolved {len(ips)} unique IP(s), {len(cname_map)} CNAME(s)")

    # 5) CDN-edge vs origin classification — so nmap doesn't waste minutes
    # deep-scanning a CDN edge (misleading "everything filtered" output).
    # One lightweight origin_ip_attribution call on the apex domain for the
    # domain-level CDN signal + any apex-only origin candidates it verifies
    # (.parsed read directly, same as the takeover check — the generic
    # Finding/graph parser for this tool only text-scrapes A:/MX_IP lines
    # and drops is_cdn/is_origin/verified entirely). Every dnsx-resolved IP
    # — not just the apex's own A records — is then classified directly via
    # the same CDN-CIDR lookup the tool itself uses (_classify_ips_by_cdn).
    _progress(f"origin_ip_attribution: classifying CDN-edge vs origin IPs for {target}")
    attribution_resp = await _exec(
        "origin_ip_attribution", {"domain": target},
        engagement_id=engagement_id, run_id=run_id, timeout=60,
    )
    attribution = attribution_resp.parsed or {}
    ip_cdn_class = _classify_ips_by_cdn(ips)
    cdn_edge_ips = {ip for ip, provider in ip_cdn_class.items() if provider}
    origin_candidate_ips = {
        str(c.get("ip") or "").strip() for c in (attribution.get("origin_candidates") or [])
    } - {""}
    ip_set = set(ips)
    origin_ips = sorted((ip_set | origin_candidate_ips) - cdn_edge_ips)
    cdn_ips = sorted(ip_set & cdn_edge_ips)
    report.cdn_edge_ips = cdn_ips
    report.origin_ips = origin_ips
    _progress(f"RESULT::classified {len(origin_ips)} origin IP(s), {len(cdn_ips)} CDN-edge IP(s)")

    # 5b) TLS SAN pass on the origin IPs too. Step 3's SAN pass only ever
    # queried hostnames — on a CDN-fronted apex that's the CDN edge's own
    # certificate, never the origin's. A direct IP:443 connection gets the
    # origin's real vhost cert, which can carry SANs DNS enumeration never
    # surfaced at all. Informational only: newly found names are recorded
    # and added to the live-probe host list below, never re-resolved or
    # re-scanned — fast-scan stays bounded, not a recursive crawler.
    if origin_ips:
        _progress(f"tlsx: inspecting TLS certs on {len(origin_ips)} origin IP(s) for SAN names")
        await _exec(
            "tlsx_inspect", {"target": "\n".join(origin_ips), "port": 443},
            engagement_id=engagement_id, run_id=run_id, timeout=60,
        )
        origin_san_nodes = graph.list_nodes(
            engagement_id=engagement_id, asset_type=AssetType.SUBDOMAIN, run_id=run_id, limit=2000,
        )
        origin_sans = {
            n.label.strip().lower() for n in origin_san_nodes
            if n.source_tool == "tlsx_inspect" and n.label.strip()
        }
        origin_sans = {
            s for s in origin_sans
            if (s == apex or s.endswith("." + apex)) and s not in set(hosts)
        }
        if origin_sans:
            report.sans_found += len(origin_sans)
            hosts = sorted({*hosts, *origin_sans})
            report.hosts_scanned = hosts
            _progress(
                f"RESULT::tlsx on origin IPs found {len(origin_sans)} new SAN host(s): "
                f"{', '.join(sorted(origin_sans)[:10])}"
            )

    # 6) httpx live-probe — converts the host list into an attack surface
    _progress(f"httpx: live-probing {len(hosts)} host(s)")
    httpx_resp = await _exec(
        "httpx_probe",
        {
            "target": "\n".join(hosts), "probe": True, "tech_detect": True,
            "status_code": True, "title": True, "web_server": True,
        },
        engagement_id=engagement_id, run_id=run_id, timeout=120,
    )
    live_urls = [t for t in (httpx_resp.finding_titles or []) if t.startswith("http")]
    report.live_urls = live_urls
    report.live_hosts = len(live_urls)
    _progress(f"RESULT::httpx found {len(live_urls)} live host(s)")

    # 7) nmap deep scan — full on origin IPs, light (80/443 only) on CDN edges
    if not origin_ips and not cdn_ips:
        report.stopped_reason = "no_ips_resolved"
        _progress("RESULT::no IPs resolved — nothing to port-scan, stopping")
    else:
        for ip in origin_ips:
            _progress(f"nmap: fast port sweep on origin {ip} (SYN, min-rate {_NMAP_MIN_RATE})")
            sweep_resp = await _exec(
                "nmap_custom_scan", {"target": ip, "flags": _NMAP_DISCOVERY_FLAGS},
                engagement_id=engagement_id, run_id=run_id, timeout=300,
            )
            open_ports = _extract_open_ports(sweep_resp.finding_titles or [])
            if not sweep_resp.success or not open_ports:
                report.nmap_results.append(
                    NmapResult(
                        ip=ip, success=bool(sweep_resp.success), scan_type="full",
                        finding_titles=[],
                        error="" if not open_ports and sweep_resp.success else (sweep_resp.error or "")[:300],
                    )
                )
                _progress(f"RESULT::nmap {ip} (origin): sweep found no open ports — skipping service/OS probe")
                continue

            _progress(
                f"nmap: service+OS detection on {ip}, {len(open_ports)} open port(s) "
                f"({','.join(open_ports)}), no forced rate"
            )
            nmap_resp = await _exec(
                "nmap_custom_scan",
                {"target": ip, "flags": _NMAP_SERVICE_FLAGS_TMPL.format(ports=",".join(open_ports))},
                engagement_id=engagement_id, run_id=run_id, timeout=600,
            )
            titles = list(nmap_resp.finding_titles or [])[:20]
            report.nmap_results.append(
                NmapResult(
                    ip=ip, success=bool(nmap_resp.success), scan_type="full", finding_titles=titles,
                    error=(nmap_resp.error or "")[:300] if not nmap_resp.success else "",
                )
            )
            _progress(
                f"RESULT::nmap {ip} (origin): {'ok' if nmap_resp.success else 'failed'} — "
                f"{len(titles)} finding(s)"
            )
        for ip in cdn_ips:
            _progress(f"nmap: light-checking CDN edge {ip} (80/443 only)")
            nmap_resp = await _exec(
                "nmap_custom_scan", {"target": ip, "flags": _NMAP_LIGHT_FLAGS},
                engagement_id=engagement_id, run_id=run_id, timeout=180,
            )
            titles = list(nmap_resp.finding_titles or [])[:20]
            report.nmap_results.append(
                NmapResult(
                    ip=ip, success=bool(nmap_resp.success), scan_type="light", finding_titles=titles,
                    error=(nmap_resp.error or "")[:300] if not nmap_resp.success else "",
                )
            )
            _progress(
                f"RESULT::nmap {ip} (cdn-edge): {'ok' if nmap_resp.success else 'failed'} — "
                f"{len(titles)} finding(s)"
            )

    # 8) Dangling-CNAME takeover check — cheap DNS+HTTP checks, only if any
    # CNAMEs were actually found (no CNAMEs = nothing to check).
    if cname_map:
        hosts_with_cname = sorted(cname_map.keys())
        _progress(f"subdomain_takeover_check: checking {len(hosts_with_cname)} CNAME host(s)")
        takeover_resp = await _exec(
            "subdomain_takeover_check",
            {"target": "", "mode": "list", "subdomains": "\n".join(hosts_with_cname), "max_hosts": 50},
            engagement_id=engagement_id, run_id=run_id, timeout=180,
        )
        # Read the tool's own structured output directly rather than
        # finding_titles — finding_titles only carries entries the deterministic
        # parser (parse_subdomain_takeover) turned into Findings, which is
        # nothing at all when every host comes back "safe"; on a genuinely
        # empty result the platform's generic fallback still emits one
        # unparsed-observation Finding to preserve raw output for agent
        # context (by design), which finding_titles can't be told apart from
        # a real risk here.
        parsed = takeover_resp.parsed or {}
        flagged = list(parsed.get("vulnerable") or []) + list(parsed.get("potential") or [])
        report.takeover_flags = [
            f"{str(r.get('status') or 'flagged').upper()}: {r.get('subdomain')} -> "
            f"{r.get('cname')} ({r.get('service') or 'unknown service'})"
            for r in flagged
        ]
        _progress(f"RESULT::takeover check flagged {len(report.takeover_flags)} host(s)")

    return report
