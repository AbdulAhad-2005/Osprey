"""Canonical engagement report — ONE standards-aligned structure, one source.

The platform historically had three partial report paths: ``report_generator``
(honest structured dossier, used by ``platform_report_data``), ``markdown_report``
(a recon inventory dump, used by the CLI ``/report``), and ``report_outline`` (a
findings outline). None was a professional deliverable: a reader wants an
executive summary with an overall risk rating, the scope / rules of engagement,
the methodology actually followed, the findings with evidence and remediation,
and a recon appendix — in that order, from one assembled source.

This module is that one source. It REUSES ``report_generator.build_report_data``
(which already separates observed facts / scanner claims / brain-authored
conclusions honestly) and wraps it with the report framing. The same canonical
dict renders to the GUI (React) and to Markdown (``render_markdown``) so the
on-screen report and every export agree by construction.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from osprey.schemas.observation import Observation
from osprey.services.engagement_store import get_engagement_store
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store
from osprey.services.report_generator import build_report_data

_SEV_ORDER = ["critical", "high", "medium", "low", "info", "none"]
_RISK_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
    "none": "Informational",
}

# Which tool → which methodology phase, so "what we did" reflects real tool runs.
_TOOL_PHASE: list[tuple[str, list[str]]] = [
    ("Reconnaissance & Enumeration", [
        "subfinder", "amass", "crt_sh", "crt.sh", "domain_hunter", "dnsx", "dnsenum", "whois",
        "tlsx", "gau", "wayback", "hakrawler", "katana", "feroxbuster", "ffuf", "gobuster",
        "arjun", "js_recon", "cdn_origin", "origin_ip", "subdomain_takeover", "app_recon",
        "well_known", "httpx",
    ]),
    ("Network & Service Discovery", ["nmap", "naabu", "masscan", "rustscan"]),
    ("OSINT & Exposure Intelligence", ["shodan", "intelx", "resecurity", "email_security", "web_search"]),
    ("Vulnerability Assessment", ["nuclei", "nikto", "wpscan"]),
    ("Exploitation & Validation", [
        "sqlmap", "metasploit", "msfvenom", "pwntools", "hydra", "hashcat", "john",
        "searchsploit", "canary", "response_diff", "proxy",
    ]),
]

# Recon appendix groupings (mirror the GUI's attack-surface buckets).
_APPENDIX_SECTIONS: list[tuple[str, str, list[str]]] = [
    ("subdomains", "Subdomains", ["subdomain"]),
    ("hosts", "Hosts & IPs", ["host", "ip", "asn"]),
    ("services", "Ports & Services", ["port", "service", "banner"]),
    ("web", "Web Endpoints", ["url", "endpoint", "content_path", "js_endpoint"]),
    ("technologies", "Technologies", ["technology"]),
    ("dns_tls", "DNS & TLS", ["dns_record", "cert", "waf"]),
    ("identities", "OSINT Identities", ["email", "person", "username", "phone", "social_account", "organization", "document"]),
    ("secrets", "Credentials & Secrets", ["credential", "secret"]),
]


def build_report(engagement_id: str) -> dict[str, Any]:
    """Assemble the canonical report structure for an engagement."""
    eid = (engagement_id or "").strip()
    if not eid:
        return {"error": "engagement_id required"}

    engagement = get_engagement_store().get(eid)
    if engagement is None:
        return {"error": f"engagement {eid!r} not found"}

    data = build_report_data(eid)
    findings = get_findings_store().list(engagement_id=eid, limit=5000)
    observations = get_observation_store().list_for_engagement(eid, limit=20000)

    sev_counts = {s: int(data["severity_breakdown"]["by_severity"].get(s, 0)) for s in _SEV_ORDER}
    real_findings = sum(v for s, v in sev_counts.items() if s != "none") + sev_counts["none"]
    overall_risk = _overall_risk(sev_counts)
    appendix = _recon_appendix(observations)

    return {
        "meta": {
            "engagement_id": eid,
            "target": engagement.target,
            "name": engagement.name,
            "status": engagement.status,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "started_at": engagement.created_at.isoformat() if getattr(engagement, "created_at", None) else None,
            "updated_at": engagement.updated_at.isoformat() if getattr(engagement, "updated_at", None) else None,
            "tools_executed": getattr(engagement, "tools_executed", 0),
        },
        "executive_summary": _executive_summary(engagement, data, findings, sev_counts, overall_risk, appendix),
        "scope": _scope_and_roe(engagement),
        "methodology": _methodology(observations),
        "findings_by_severity": data["findings_by_severity"],
        "scanner_claims": data["scanner_claims"],
        "infrastructure_notes": data["infrastructure_notes"],
        "technologies": data["technologies_detected"],
        "recon_appendix": appendix,
        "metrics": data["metrics"],
        "totals": {"findings": real_findings, "by_severity": sev_counts},
    }


def _overall_risk(sev_counts: dict[str, int]) -> str:
    for sev in ("critical", "high", "medium", "low"):
        if sev_counts.get(sev, 0) > 0:
            return sev
    return "info"


def _executive_summary(engagement, data, findings, sev_counts, overall_risk, appendix) -> dict[str, Any]:
    counts = {s: appendix_count(appendix, s) for s in ("subdomains", "hosts", "services", "identities", "secrets")}
    # Count the technology observations in the appendix (consistent with the
    # rest of the report) rather than report_generator's name-dedup list, which
    # only populates from tools that pack a `technology` detail (e.g. httpx).
    tech_n = appendix_count(appendix, "technologies")
    total_findings = sum(v for s, v in sev_counts.items() if s != "none") + sev_counts.get("none", 0)
    top_risks = [
        {"title": f.title, "severity": str(getattr(f.claim_severity, "value", f.claim_severity) or "none"), "target": f.target}
        for f in findings
        if str(getattr(f.claim_severity, "value", f.claim_severity) or "none").lower() in ("critical", "high")
    ][:8]

    # Deterministic, professional narrative — not an LLM paraphrase, so it is
    # always available and never hallucinates. (An LLM polish pass can replace
    # this later without changing the structure.)
    parts: list[str] = []
    parts.append(
        f"Osprey performed an evidence-driven security assessment of {engagement.target}. "
        f"Reconnaissance mapped {counts['subdomains']} subdomain(s) across {counts['hosts']} host(s), "
        f"identifying {appendix_count(appendix, 'services')} port/service observation(s) and "
        f"{tech_n} distinct technologie(s)."
    )
    if counts["identities"] or counts["secrets"]:
        parts.append(
            f"OSINT surfaced {counts['identities']} identity record(s) and "
            f"{counts['secrets']} credential/secret exposure(s)."
        )
    if total_findings:
        sev_phrase = ", ".join(
            f"{sev_counts[s]} {_RISK_LABEL[s].lower()}" for s in ("critical", "high", "medium", "low", "info") if sev_counts.get(s)
        )
        parts.append(
            f"The assessment produced {total_findings} finding(s): {sev_phrase}. "
            f"The overall risk posture is rated {_RISK_LABEL[overall_risk]}."
        )
    else:
        parts.append("No confirmed vulnerabilities were concluded during this assessment window.")

    return {
        "overall_risk": overall_risk,
        "overall_risk_label": _RISK_LABEL[overall_risk],
        "narrative": " ".join(parts),
        "key_stats": {
            "subdomains": counts["subdomains"],
            "hosts": counts["hosts"],
            "services": counts["services"],
            "technologies": tech_n,
            "identities": counts["identities"],
            "secrets": counts["secrets"],
            "findings": total_findings,
        },
        "top_risks": top_risks,
    }


def _scope_and_roe(engagement) -> dict[str, Any]:
    roe = engagement.rules_of_engagement
    scope = roe.scope
    return {
        "target": engagement.target,
        "description": roe.description,
        "in_scope": list(scope.in_scope_targets) or [engagement.target],
        "out_of_scope": list(scope.out_of_scope),
        "allowed_techniques": list(scope.allowed_techniques),
        "blocked_techniques": list(scope.blocked_techniques),
        "requires_human_approval": roe.requires_human_approval,
        "allow_exploitation": roe.allow_exploitation,
        "allow_post_exploitation": roe.allow_post_exploitation,
        "destructive_actions_allowed": roe.destructive_actions_allowed,
        "rate_limit_rps": scope.request_rate_limit,
        "max_concurrent_tools": scope.max_concurrent_tools,
        "time_window": (
            f"{scope.time_window_start}–{scope.time_window_end} UTC"
            if scope.time_window_start and scope.time_window_end
            else None
        ),
    }


def _methodology(observations: list[Observation]) -> list[dict[str, Any]]:
    tools_seen: dict[str, int] = defaultdict(int)
    for o in observations:
        if o.source_tool:
            tools_seen[o.source_tool.lower()] += 1

    phases: list[dict[str, Any]] = []
    assigned: set[str] = set()
    for phase_name, prefixes in _TOOL_PHASE:
        tools = sorted({t for t in tools_seen if any(p in t for p in prefixes)})
        if tools:
            assigned.update(tools)
            phases.append({"phase": phase_name, "tools": tools})
    extra = sorted(t for t in tools_seen if t not in assigned)
    if extra:
        phases.append({"phase": "Other", "tools": extra})
    return phases


def _recon_appendix(observations: list[Observation]) -> list[dict[str, Any]]:
    by_type: dict[str, list[Observation]] = defaultdict(list)
    for o in observations:
        by_type[o.type.value].append(o)

    sections: list[dict[str, Any]] = []
    for key, label, types in _APPENDIX_SECTIONS:
        items: list[dict[str, Any]] = []
        for t in types:
            for o in by_type.get(t, []):
                items.append({
                    "type": t,
                    "value": _obs_value(o),
                    "detail": _obs_detail(o),
                    "source_tool": o.source_tool,
                })
        if items:
            items.sort(key=lambda x: (x["type"], x["value"]))
            sections.append({"key": key, "label": label, "count": len(items), "items": items})
    return sections


def appendix_count(appendix: list[dict[str, Any]], key: str) -> int:
    for s in appendix:
        if s["key"] == key:
            return int(s["count"])
    return 0


def _obs_value(o: Observation) -> str:
    d = o.details or {}
    t = o.type.value
    if t == "port":
        return f"{o.target}:{d.get('port', '')}".rstrip(":")
    if t == "service":
        name = d.get("service") or d.get("product") or d.get("name") or ""
        return f"{name} @ {o.target}".strip(" @") if name else o.target
    if t == "technology":
        return str(d.get("name") or d.get("technology") or d.get("product") or o.target)
    if t == "credential":
        user = d.get("username") or d.get("email") or d.get("user") or ""
        secret = d.get("password") or d.get("secret") or d.get("value") or ""
        return f"{user}:{secret}" if user and secret else (str(user) or str(secret) or o.target)
    if t in ("email", "person", "phone", "secret"):
        return str(d.get("email") or d.get("name") or d.get("phone") or d.get("secret") or d.get("value") or o.target)
    return o.target or str(d.get("value") or d.get("name") or o.signature or "—")


def _obs_detail(o: Observation) -> str:
    d = o.details or {}
    t = o.type.value
    if t in ("subdomain", "host"):
        return str(d.get("ip") or d.get("status_code") or d.get("status") or "")
    if t == "port":
        return str(d.get("service") or d.get("state") or "")
    if t == "service":
        return " ".join(str(d.get(k)) for k in ("product", "version") if d.get(k))
    if t == "technology":
        return str(d.get("version") or "")
    if t == "credential":
        return str(d.get("source") or d.get("breach") or "")
    return ""


# --------------------------------------------------------------------------- #
# Markdown rendering — the same canonical dict, serialized for export / CLI.   #
# --------------------------------------------------------------------------- #

def render_markdown(report: dict[str, Any]) -> str:
    if "error" in report:
        return f"# Report unavailable\n\n{report['error']}\n"
    m = report["meta"]
    es = report["executive_summary"]
    out: list[str] = []
    out.append(f"# Penetration Test Report — {m['target']}")
    out.append("")
    out.append(f"**Overall risk:** {es['overall_risk_label']}  ")
    out.append(f"**Engagement:** `{m['engagement_id']}`  ·  **Status:** {m['status']}  ·  **Generated:** {m['generated_at'][:19]}Z")
    out.append("")
    out.append("## Executive Summary")
    out.append("")
    out.append(es["narrative"])
    out.append("")
    ks = es["key_stats"]
    out.append("| Metric | Count |")
    out.append("| --- | ---: |")
    for label, key in [("Subdomains", "subdomains"), ("Hosts", "hosts"), ("Services", "services"),
                       ("Technologies", "technologies"), ("OSINT identities", "identities"),
                       ("Credentials/secrets", "secrets"), ("Findings", "findings")]:
        out.append(f"| {label} | {ks.get(key, 0)} |")
    out.append("")
    if es["top_risks"]:
        out.append("**Top risks:**")
        for r in es["top_risks"]:
            out.append(f"- _{r['severity'].title()}_ — {r['title']} (`{r['target']}`)")
        out.append("")

    sc = report["scope"]
    out.append("## Scope & Rules of Engagement")
    out.append("")
    out.append(f"- **In scope:** {', '.join(sc['in_scope']) or '—'}")
    out.append(f"- **Out of scope:** {', '.join(sc['out_of_scope']) or '—'}")
    out.append(f"- **Exploitation allowed:** {'yes' if sc['allow_exploitation'] else 'no'}")
    out.append(f"- **Destructive actions allowed:** {'yes' if sc['destructive_actions_allowed'] else 'no'}")
    out.append(f"- **Rate limit:** {sc['rate_limit_rps']} req/s · **Max concurrent tools:** {sc['max_concurrent_tools']}")
    out.append("")

    out.append("## Methodology")
    out.append("")
    if report["methodology"]:
        for ph in report["methodology"]:
            out.append(f"- **{ph['phase']}:** {', '.join(ph['tools'])}")
    else:
        out.append("_No tool activity recorded._")
    out.append("")

    out.append("## Findings")
    out.append("")
    groups = report["findings_by_severity"]
    if not groups:
        out.append("_No confirmed findings._")
        out.append("")
    for g in groups:
        out.append(f"### {g['severity'].title()} ({g['count']})")
        out.append("")
        for f in g["findings"]:
            out.append(f"#### {f['title']}")
            out.append("")
            out.append(f"- **Target:** `{f['target'] or '—'}`  ·  **Confidence:** {f['confidence']}  ·  **Source:** {f['source_tool'] or '—'}")
            if f.get("description"):
                out.append("")
                out.append(f["description"])
            if f.get("evidence_snippet"):
                out.append("")
                out.append("**Evidence:**")
                out.append("")
                out.append("```")
                out.append(f["evidence_snippet"])
                out.append("```")
            out.append("")
            out.append(f"**Remediation:** {f['remediation_hint']}")
            out.append("")

    if report["scanner_claims"]:
        out.append("## Unverified Scanner Claims")
        out.append("")
        out.append("_Raw scanner matches, not confirmed findings — each requires verification._")
        out.append("")
        for c in report["scanner_claims"]:
            out.append(f"- `{c['source_tool']}` — {c['title']} ({c['target']}) · claimed: {c['scanner_claimed_severity']}")
        out.append("")

    out.append("## Appendix — Attack Surface Inventory")
    out.append("")
    for sec in report["recon_appendix"]:
        out.append(f"### {sec['label']} ({sec['count']})")
        out.append("")
        out.append("| Value | Detail | Source |")
        out.append("| --- | --- | --- |")
        for it in sec["items"]:
            out.append(f"| `{it['value']}` | {it['detail'] or ''} | {it['source_tool'] or ''} |")
        out.append("")

    out.append("---")
    out.append("")
    out.append("_Generated by Osprey._")
    return "\n".join(out)
