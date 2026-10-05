"""Structured report data engine — an honest three-source dossier.

Plan 19: the handoff a human (or LLM) reads must keep three things visibly
separate and never conflate them:

  * OBSERVED FACTS      — structural truth from the asset GRAPH + observations
                          (domains/subdomains/hosts/ports/services/URLs/tech).
  * SCANNER CLAIMS      — unverified SCANNER_SIGNAL observations (a nuclei/nikto
                          match is a claim, labelled as such, never a finding).
  * CONCLUSIONS         — brain-authored FINDINGS only (findings_store now holds
                          conclusions exclusively; the deterministic engine
                          manufactures none).

Earlier this module read ``findings_store`` for everything — infrastructure,
technology, severity — which in the no-LLM path (where nothing auto-creates a
finding) produced an empty dossier, and historically dressed raw scanner noise
up as findings. Facts/tech/infra now come from the graph + observations, scanner
claims from observations, and only genuine conclusions from findings.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from osprey.schemas.observation import Observation, ObservationType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store
from osprey.services.phase_supervisor import phase_readiness_snapshot
from osprey.services.visualization import generate_mermaid


_REMEDIATION_HINTS = {
    "xss": "Implement context-aware HTML entity encoding and enforce a strong Content Security Policy (CSP).",
    "sqli": "Use parameterized queries / prepared statements for all database access.",
    "cors": "Restrict Access-Control-Allow-Origin to trusted domains and avoid combining wildcard '*' with Allow-Credentials: true.",
    "eol": "Upgrade software stack to an actively supported version to receive security patches.",
    "jwt": "Enforce signature verification with strong algorithms and validate key expiration/claims.",
    "subdomain_takeover": "Remove dangling CNAME / DNS records pointing to unallocated third-party resources.",
    "exposure": "Restrict public access to sensitive endpoints/documents via authentication or IP whitelisting.",
}


def _remediation_hint(title: str, description: str) -> str:
    combined = f"{title} {description}".lower()
    for kw, hint in _REMEDIATION_HINTS.items():
        if kw in combined:
            return hint
    return "Remediate by applying least-privilege access controls and updating affected components."


def build_report_data(engagement_id: str) -> dict[str, Any]:
    """Aggregate engagement data into a structured, honestly-sectioned report."""
    eid = (engagement_id or "").strip()
    if not eid:
        return {"error": "engagement_id required"}

    findings = get_findings_store().list(engagement_id=eid, limit=5000)
    observations = get_observation_store().list_for_engagement(eid, limit=20000)
    graph = get_engagement_graph()
    nodes = graph.list_nodes(engagement_id=eid, limit=10000)
    edges = graph.list_edges(engagement_id=eid, limit=30000)

    scanner_claims = [o for o in observations if o.type == ObservationType.SCANNER_SIGNAL]
    readiness = phase_readiness_snapshot(eid)

    return {
        "engagement_id": eid,
        "metrics": _build_metrics(findings, scanner_claims, observations, nodes, edges),
        # CONCLUSIONS — brain-authored findings only.
        "severity_breakdown": _build_severity_breakdown(findings),
        "findings_by_severity": _build_findings_by_severity(findings),
        # SCANNER CLAIMS — unverified, sourced from observations, never findings.
        "scanner_claims": _build_scanner_claims(scanner_claims),
        # OBSERVED FACTS — from graph + observations.
        "infrastructure_notes": _build_infra_notes(observations, nodes),
        "technologies_detected": _build_tech_summary(observations, nodes),
        "phase_readiness": readiness,
        "topology": generate_mermaid(eid),
    }


def _build_metrics(
    findings: list,
    scanner_claims: list,
    observations: list,
    nodes: list,
    edges: list,
) -> dict[str, Any]:
    conclusion_types = Counter(f.finding_type.value for f in findings)
    node_type_counts = Counter(n.asset_type.value for n in nodes)
    observation_types = Counter(o.type.value for o in observations)

    return {
        "total_conclusions": len(findings),
        "total_scanner_claims": len(scanner_claims),
        "total_observations": len(observations),
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "conclusions_by_type": dict(conclusion_types),
        "observations_by_type": dict(observation_types),
        "assets_by_type": dict(node_type_counts),
    }


def _build_severity_breakdown(findings: list) -> dict[str, Any]:
    sev_counts = Counter(
        str(getattr(f.claim_severity, "value", f.claim_severity) or "none").lower()
        for f in findings
    )
    confidence_counts = Counter(
        str(getattr(f.confidence, "value", f.confidence) or "likely").lower()
        for f in findings
    )
    return {
        "by_severity": dict(sev_counts),
        "by_confidence": dict(confidence_counts),
    }


def _build_findings_by_severity(findings: list) -> list[dict[str, Any]]:
    """Brain-authored conclusions grouped and sorted by severity, most severe first."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}
    grouped: dict[str, list[dict[str, Any]]] = {}

    for f in findings:
        sev = str(getattr(f.claim_severity, "value", f.claim_severity) or "none").lower()
        grouped.setdefault(sev, []).append({
            "id": f.id,
            "type": f.finding_type.value,
            "title": f.title,
            "description": f.description,
            "severity": sev,
            "confidence": str(getattr(f.confidence, "value", f.confidence) or ""),
            "source_tool": f.source_tool,
            "target": f.target,
            "evidence_snippet": (f.evidence or "")[:1000],
            "remediation_hint": _remediation_hint(f.title, f.description),
        })

    return [
        {"severity": sev, "count": len(items), "findings": items}
        for sev, items in sorted(
            grouped.items(),
            key=lambda x: severity_order.get(x[0], 5),
        )
        if items
    ]


def _build_scanner_claims(scanner_claims: list[Observation]) -> list[dict[str, Any]]:
    """Unverified scanner matches, straight from SCANNER_SIGNAL observations.
    Explicitly NOT findings — a human/LLM verifies before any conclusion. Carries
    the scanner's own claimed severity as metadata, never promoted to Osprey's."""
    out: list[dict[str, Any]] = []
    for o in scanner_claims:
        d = o.details or {}
        out.append({
            "observation_id": o.id,
            "source_tool": o.source_tool,
            "target": o.target,
            "title": str(d.get("title") or d.get("claim") or o.target or o.type.value),
            "scanner_claimed_severity": str(d.get("claimed_severity") or "unknown"),
            "template_id": str(d.get("template_id") or d.get("signature") or ""),
            "verified": False,
        })
    return out


def _build_infra_notes(observations: list[Observation], nodes: list) -> dict[str, Any]:
    """Infrastructure posture from observations (WAF/CDN/email) + graph."""
    waf_detected: set[str] = set()
    cloudflare: set[str] = set()
    email_posture: set[str] = set()

    for o in observations:
        d = o.details or {}
        tags = {str(t).lower() for t in (o.tags or [])}
        if o.type == ObservationType.WAF or "waf" in tags:
            label = str(d.get("waf") or o.target or d.get("title") or "")
            if label:
                waf_detected.add(label if o.type != ObservationType.WAF else f"{o.target}: {label}".strip(": "))
        if d.get("is_cloudflare") or d.get("cloudflare") or "cloudflare" in tags:
            cloudflare.add(str(d.get("hostname") or o.target or ""))
        if o.type == ObservationType.DNS_RECORD and any(
            k in str(d).lower() for k in ("spf", "dkim", "dmarc", "dnssec")
        ):
            email_posture.add(str(d.get("title") or o.target or ""))

    return {
        "waf_detected": sorted(x for x in waf_detected if x),
        "cloudflare_assets": sorted(x for x in cloudflare if x),
        "email_posture": sorted(x for x in email_posture if x),
    }


def _build_tech_summary(observations: list[Observation], nodes: list) -> list[str]:
    """Deduplicated technology list from TECHNOLOGY observations + graph nodes."""
    techs: set[str] = set()
    for o in observations:
        d = o.details or {}
        tech = d.get("technology")
        if isinstance(tech, str) and tech:
            # httpx packs a comma-separated tech group into one string.
            for part in tech.split(","):
                part = part.strip()
                if part:
                    techs.add(part)
    for n in nodes:
        if n.asset_type.value == "technology":
            techs.add(n.label)
    return sorted(techs)[:100]
