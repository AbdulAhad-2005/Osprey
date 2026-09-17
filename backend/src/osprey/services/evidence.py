"""Finding normalization + noise downgrades."""

from __future__ import annotations

from typing import Iterable

from osprey.schemas.finding import (
    ClaimSeverity,
    Finding,
    FindingConfidence,
    FindingType,
)

# Hosts with this many open ports and almost no SERVICE findings → decoy/noise.
PORT_FLOOD_THRESHOLD = 40
PORT_FLOOD_MIN_SERVICES = 3


def normalize_finding(finding: Finding) -> Finding:
    """Re-run through model validation (idempotent)."""
    return Finding.model_validate(finding.model_dump())


def normalize_findings(findings: Iterable[Finding]) -> list[Finding]:
    return [normalize_finding(f) for f in findings]


def apply_port_flood_downgrades(findings: list[Finding]) -> list[Finding]:
    """Mark port-flood hosts: many PORT rows, few SERVICE → unverified + tag."""
    ports_by_host: dict[str, list[Finding]] = {}
    services_by_host: dict[str, int] = {}

    for f in findings:
        host = _host_key(f)
        if not host:
            continue
        if f.finding_type == FindingType.PORT:
            ports_by_host.setdefault(host, []).append(f)
        elif f.finding_type == FindingType.SERVICE:
            services_by_host[host] = services_by_host.get(host, 0) + 1

    flood_hosts = {
        h
        for h, ports in ports_by_host.items()
        if len(ports) >= PORT_FLOOD_THRESHOLD
        and services_by_host.get(h, 0) < PORT_FLOOD_MIN_SERVICES
    }
    if not flood_hosts:
        return findings

    out: list[Finding] = []
    for f in findings:
        host = _host_key(f)
        if host in flood_hosts and f.finding_type in (
            FindingType.PORT,
            FindingType.SERVICE,
            FindingType.OBSERVATION,
        ):
            tags = list(f.tags or [])
            if "honeypot_suspect" not in tags:
                tags.append("honeypot_suspect")
            if "port_flood" not in tags:
                tags.append("port_flood")
            f = f.model_copy(
                update={
                    "tags": tags,
                    "confidence": FindingConfidence.HYPOTHESIS,
                    "claim_severity": ClaimSeverity.INFO,
                    "notes": (
                        (f.notes + " " if f.notes else "")
                        + f"Port-flood on {host}: treat as decoy/noise until "
                        "2–3 services are banner-verified."
                    ).strip(),
                }
            )
            f = normalize_finding(f)
        out.append(f)
    return out


def _host_key(f: Finding) -> str:
    meta = f.metadata or {}
    for key in ("ip", "hostname", "host"):
        val = str(meta.get(key) or "").strip().lower()
        if val:
            return val
    title = (f.title or "").strip().lower()
    if not title:
        return ""
    # ip:port or host:port
    if ":" in title and title.count(":") == 1:
        left, right = title.split(":", 1)
        if right.isdigit():
            return left
    # URL-ish
    if "://" in title:
        return title.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
    return title
