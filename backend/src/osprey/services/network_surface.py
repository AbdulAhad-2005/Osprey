"""Compute per-IP network surface: ports_known vs services_known (M5).

Best-effort from graph + findings. Soft — incomplete parses leave flags false
without claiming the work was never done.
"""

from __future__ import annotations

import re

from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.finding import Finding, FindingType
from osprey.schemas.network_surface import (
    HostNetworkState,
    IpNetworkState,
    NetworkSurfaceSummary,
)
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.findings_store import get_findings_store

_HOST_ASSET_TYPES = (AssetType.HOST, AssetType.SUBDOMAIN)

_PORT_NUM_RE = re.compile(r"(?:^|[:/])(\d{1,5})(?:/|$|\s)")


def build_network_surface(
    engagement_id: str,
    *,
    run_id: str = "",
) -> NetworkSurfaceSummary | None:
    if not engagement_id:
        return None

    findings = get_findings_store().list(
        engagement_id=engagement_id,
        run_id=None,  # engagement-wide memory
        limit=5000,
    )
    graph = get_engagement_graph()
    nodes = graph.list_nodes(engagement_id=engagement_id, limit=10_000)
    edges = graph.list_edges(engagement_id=engagement_id, limit=50_000)

    ip_nodes = [n for n in nodes if n.asset_type == AssetType.IP]
    node_by_id = {n.id: n for n in nodes}

    # host_node_id -> ip_label
    host_to_ips: dict[str, set[str]] = {}
    for e in edges:
        if e.relationship != "resolves_to":
            continue
        ip_n = node_by_id.get(e.target_id)
        if ip_n is None or ip_n.asset_type != AssetType.IP:
            continue
        host_to_ips.setdefault(e.source_id, set()).add(ip_n.label)

    # ip -> ports / services
    ports_by_ip: dict[str, set[str]] = {n.label: set() for n in ip_nodes}
    services_by_ip: dict[str, set[str]] = {n.label: set() for n in ip_nodes}
    hosts_by_ip: dict[str, set[str]] = {n.label: set() for n in ip_nodes}

    for host_id, ips in host_to_ips.items():
        host_n = node_by_id.get(host_id)
        label = host_n.label if host_n else host_id.split(":", 1)[-1]
        for ip in ips:
            hosts_by_ip.setdefault(ip, set()).add(label.lower())

    # Ports via has_port edges
    for e in edges:
        if e.relationship != "has_port":
            continue
        host_n = node_by_id.get(e.source_id)
        port_n = node_by_id.get(e.target_id)
        if not host_n or not port_n:
            continue
        port_token = _normalize_port(port_n.label)
        if not port_token:
            continue
        for ip in host_to_ips.get(e.source_id, set()):
            ports_by_ip.setdefault(ip, set()).add(port_token)

    # PORT nodes labeled "ip:port"
    for n in nodes:
        if n.asset_type != AssetType.PORT:
            continue
        for ip_n in ip_nodes:
            if n.label.startswith(ip_n.label + ":"):
                token = _normalize_port(n.label)
                if token:
                    ports_by_ip.setdefault(ip_n.label, set()).add(token)

    # Findings: PORT / SERVICE
    for f in findings:
        if f.finding_type == FindingType.PORT:
            ips = _ips_for_finding(f, host_to_ips, node_by_id, ip_nodes)
            token = _normalize_port(str(f.metadata.get("port") or f.title))
            if not token:
                continue
            for ip in ips:
                ports_by_ip.setdefault(ip, set()).add(token)
                hosts_by_ip.setdefault(ip, set())
        elif f.finding_type == FindingType.SERVICE:
            ips = _ips_for_finding(f, host_to_ips, node_by_id, ip_nodes)
            svc = f.title.strip()
            port_token = _normalize_port(str(f.metadata.get("port") or ""))
            for ip in ips:
                if svc:
                    services_by_ip.setdefault(ip, set()).add(svc)
                if port_token:
                    ports_by_ip.setdefault(ip, set()).add(port_token)
                hosts_by_ip.setdefault(ip, set())

    # Host-keyed pass — walks has_port/runs_service edges directly from the
    # host node, so a host with real port/service data is never invisible
    # just because it has no resolves_to->IP edge (see HostNetworkState docstring).
    host_nodes = [n for n in nodes if n.asset_type in _HOST_ASSET_TYPES]
    ports_by_host: dict[str, set[str]] = {n.id: set() for n in host_nodes}
    services_by_host: dict[str, set[str]] = {n.id: set() for n in host_nodes}
    port_node_to_host: dict[str, str] = {}

    for e in edges:
        if e.relationship != "has_port" or e.source_id not in ports_by_host:
            continue
        port_n = node_by_id.get(e.target_id)
        if not port_n:
            continue
        token = _normalize_port(port_n.label)
        if not token:
            continue
        ports_by_host[e.source_id].add(token)
        port_node_to_host[e.target_id] = e.source_id

    for e in edges:
        if e.relationship != "runs_service":
            continue
        host_id = port_node_to_host.get(e.source_id)
        if not host_id:
            continue
        svc_n = node_by_id.get(e.target_id)
        if svc_n and svc_n.label:
            services_by_host[host_id].add(svc_n.label)

    host_states: list[HostNetworkState] = []
    for n in sorted(host_nodes, key=lambda x: x.label):
        ports = sorted(ports_by_host.get(n.id, set()), key=_port_sort_key)
        services = sorted(services_by_host.get(n.id, set()))
        ports_known = bool(ports)
        services_known = bool(services)
        note = ""
        if ports_known and not services_known:
            note = "Ports known without service/version evidence"
        elif not ports_known:
            note = "No structured port evidence yet"
        host_states.append(
            HostNetworkState(
                host=n.label,
                ports=ports,
                services=services,
                ports_known=ports_known,
                services_known=services_known,
                notes=note,
            )
        )

    states: list[IpNetworkState] = []
    for ip_n in sorted(ip_nodes, key=lambda n: n.label):
        ports = sorted(ports_by_ip.get(ip_n.label, set()), key=_port_sort_key)
        services = sorted(services_by_ip.get(ip_n.label, set()))
        hosts = sorted(hosts_by_ip.get(ip_n.label, set()))
        ports_known = bool(ports)
        services_known = bool(services)
        note = ""
        if ports_known and not services_known:
            note = "Ports known without service/version evidence"
        elif not ports_known:
            note = "No structured port evidence yet"
        states.append(
            IpNetworkState(
                ip=ip_n.label,
                hosts=hosts,
                ports=ports,
                services=services,
                ports_known=ports_known,
                services_known=services_known,
                notes=note,
            )
        )

    return NetworkSurfaceSummary(
        engagement_id=engagement_id,
        ips=states,
        unscanned_ips=sum(1 for s in states if not s.ports_known),
        ports_without_services=sum(1 for s in states if s.ports_known and not s.services_known),
        hosts=host_states,
        unscanned_hosts=sum(1 for s in host_states if not s.ports_known),
        hosts_ports_without_services=sum(
            1 for s in host_states if s.ports_known and not s.services_known
        ),
    )


def network_surface_text(summary: NetworkSurfaceSummary, *, max_lines: int = 25) -> str:
    lines = [
        f"ips={len(summary.ips)} unscanned={summary.unscanned_ips} "
        f"ports_no_services={summary.ports_without_services}"
    ]
    if summary.hosts:
        lines.append(
            f"hosts={len(summary.hosts)} unscanned={summary.unscanned_hosts} "
            f"ports_no_services={summary.hosts_ports_without_services} "
            "(host-keyed — catches gaps the IP view misses when DNS wasn't resolved to an IP node)"
        )
    for st in summary.ips[:20]:
        if not st.ports_known:
            lines.append(f"  - {st.ip} ports_known=false hosts={','.join(st.hosts[:3]) or '-'}")
        elif not st.services_known:
            lines.append(
                f"  - {st.ip} ports={','.join(st.ports[:8])} services_known=false"
            )
        else:
            lines.append(
                f"  - {st.ip} ports={','.join(st.ports[:6])} services={len(st.services)}"
            )
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + "\n…"
    return "\n".join(lines)


def _normalize_port(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if raw.isdigit():
        return raw
    m = _PORT_NUM_RE.search(raw)
    return m.group(1) if m else ""


def _port_sort_key(p: str) -> tuple:
    return (0, int(p)) if p.isdigit() else (1, p)


def _ips_for_finding(f: Finding, host_to_ips, node_by_id, ip_nodes) -> set[str]:
    ips: set[str] = set()
    # Direct IP in title/target/metadata
    candidates = [
        str(f.metadata.get("ip", "") or ""),
        f.target or "",
        f.title.split(":")[0] if ":" in f.title else "",
    ]
    ip_labels = {n.label for n in ip_nodes}
    for c in candidates:
        c = c.strip()
        if c in ip_labels:
            ips.add(c)

    host = (f.target or "").strip().lower()
    if not host and f.finding_type == FindingType.PORT and ":" in f.title:
        host = f.title.split(":")[0].lower()
    meta_host = str(f.metadata.get("hostname") or f.metadata.get("host") or "").lower()
    for h in (host, meta_host):
        if not h:
            continue
        for prefix in (AssetType.HOST, AssetType.SUBDOMAIN):
            nid = f"{prefix.value}:{h}"
            ips.update(host_to_ips.get(nid, set()))
    return ips
