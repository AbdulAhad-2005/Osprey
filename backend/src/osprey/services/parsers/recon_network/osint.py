"""Passive OSINT parsers (Shodan search / host info)."""

from __future__ import annotations

import json

from osprey.schemas.observation import Observation, ObservationType


def parse_shodan_search(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    try:
        data = json.loads(stdout or "")
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    for match in data.get("matches") or []:
        if not isinstance(match, dict):
            continue
        ip = str(match.get("ip") or "").strip()
        port = match.get("port")
        hostnames = [str(h).lower() for h in (match.get("hostnames") or []) if h]
        if ip:
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.HOST,
                    target=target or ip,
                    source_tool="shodan_search",
                    details={
                        "ip": ip,
                        "port": port,
                        "org": match.get("org"),
                        "product": match.get("product"),
                        "hostnames": hostnames[:10],
                        "hostname": hostnames[0] if hostnames else "",
                    },
                    tags=["shodan", "passive"],
                )
            )
        if ip and port is not None:
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.PORT,
                    target=target or ip,
                    source_tool="shodan_search",
                    details={
                        "ip": ip,
                        "port": str(port),
                        "protocol": str(match.get("transport") or "tcp"),
                        "product": match.get("product") or "",
                        "banner": (match.get("banner") or "")[:400],
                    },
                    tags=["shodan", "passive", "port"],
                )
            )
        for host in hostnames[:5]:
            out.append(
                Observation(
                    engagement_id=engagement_id,
                    run_id=run_id,
                    type=ObservationType.SUBDOMAIN,
                    target=target or host,
                    source_tool="shodan_search",
                    details={"hostname": host, "ip": ip},
                    tags=["shodan", "passive"],
                )
            )
    return out


def parse_shodan_host_info(
    stdout: str,
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
) -> list[Observation]:
    try:
        data = json.loads(stdout or "")
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, dict) or data.get("error"):
        return []
    ip = str(data.get("ip") or target or "").strip()
    out: list[Observation] = []
    if ip:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.HOST,
                target=target or ip,
                source_tool="shodan_host_info",
                details={
                    "ip": ip,
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "os": data.get("os"),
                    "ports": data.get("ports"),
                    "hostnames": data.get("hostnames"),
                },
                tags=["shodan", "passive"],
            )
        )
    os_name = str(data.get("os") or "").strip()
    if os_name and ip:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.BANNER,
                target=target or ip,
                source_tool="shodan_host_info",
                details={"os": os_name},
                tags=["os", "os_detected", "shodan"],
            )
        )
    for port in data.get("ports") or []:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.PORT,
                target=target or ip,
                source_tool="shodan_host_info",
                details={"ip": ip, "port": str(port), "protocol": "tcp"},
                tags=["shodan", "passive", "port"],
            )
        )
    for host in (data.get("hostnames") or [])[:20]:
        host_s = str(host).strip().lower()
        if not host_s:
            continue
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SUBDOMAIN,
                target=target or host_s,
                source_tool="shodan_host_info",
                details={"hostname": host_s, "ip": ip},
                tags=["shodan", "passive"],
            )
        )
    vulns = data.get("vulns") or []
    if vulns:
        out.append(
            Observation(
                engagement_id=engagement_id,
                run_id=run_id,
                type=ObservationType.SCANNER_SIGNAL,
                target=target or ip,
                source_tool="shodan_host_info",
                details={
                    "kind": "shodan_cve_tags",
                    "title": f"Shodan indexed vulns on {ip}",
                    "description": "Shodan CVE tags are leads — verify before claiming impact",
                    "evidence": ", ".join(str(v) for v in vulns[:30]),
                    "ip": ip,
                    "vuln_count": len(vulns),
                    "cves": [str(v) for v in vulns[:30]],
                    "claimed_severity": "info",
                    "extracted": False,
                },
                tags=["shodan", "cve_lead", "unverified"],
            )
        )
    return out


