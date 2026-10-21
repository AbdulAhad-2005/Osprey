"""Canonical engagement report — ONE standards-aligned structure, one source.

The platform historically had three partial report paths: ``report_generator``
(honest structured dossier, used by ``platform_report_data``), ``markdown_report``
(a recon inventory dump, used by the CLI ``/report``), and ``report_outline`` (a
findings outline). None was a professional deliverable: a reader wants an
executive summary with an overall risk rating, the scope / rules of engagement,
the methodology actually followed, the findings with evidence and remediation,
and a recon appendix — in that order, from one assembled source.

This module is that one source. It reuses report_generator's section builders
without assembling a second dossier or graph. Legacy facts remain in the
inventory, not security-conclusion totals. The same canonical
dict renders to the GUI (React) and to Markdown (``render_markdown``) so the
on-screen report and every export agree by construction.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import re
import ipaddress
from typing import Any

from osprey.schemas.observation import Observation
from osprey.services.engagement_store import get_engagement_store
from osprey.services.findings_store import get_findings_store
from osprey.services.observation_store import get_observation_store
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.report_classification import partition_findings
from osprey.services.report_generator import (
    _build_findings_by_severity, _build_severity_breakdown, _build_scanner_claims,
    _build_infra_notes, _build_tech_summary,
)

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
    ("domains", "Domains", ["domain"]),
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

    all_findings = get_findings_store().list(engagement_id=eid, limit=10000, exclude_noise=False)
    findings, supporting = partition_findings(all_findings)
    observations = get_observation_store().list_for_engagement(eid, limit=10000)
    nodes = get_engagement_graph().list_nodes(engagement_id=eid, limit=20000)
    capped = [name for name, rows, cap in (("finding rows", all_findings, 10000), ("observations", observations, 10000),
                                          ("graph assets", nodes, 20000)) if len(rows) >= cap]
    data = {
        "severity_breakdown": _build_severity_breakdown(findings),
        "findings_by_severity": _build_findings_by_severity(findings),
        "scanner_claims": _build_scanner_claims([o for o in observations if o.type.value == "scanner_signal"]),
        "infrastructure_notes": _build_infra_notes(observations, nodes),
        "technologies_detected": _build_tech_summary(observations, nodes),
        "metrics": {"total_observations": len(observations), "total_nodes": len(nodes), "supporting_records": len(supporting)},
    }

    sev_counts = {s: int(data["severity_breakdown"]["by_severity"].get(s, 0)) for s in _SEV_ORDER}
    real_findings = sum(v for s, v in sev_counts.items() if s != "none") + sev_counts["none"]
    overall_risk = _overall_risk(sev_counts)
    appendix = _recon_appendix(observations, supporting, nodes)
    evidence_summary = _execution_summary(eid)

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
        "methodology": _methodology(observations, evidence_summary["tools"]),
        "findings_by_severity": data["findings_by_severity"],
        "scanner_claims": data["scanner_claims"],
        "review_candidates": [f for group in _build_findings_by_severity(supporting)
                              if group["severity"] != "none" for f in group["findings"]],
        "infrastructure_notes": data["infrastructure_notes"],
        "technologies": data["technologies_detected"],
        "recon_appendix": appendix,
        "metrics": data["metrics"],
        "supporting_records": {"count": len(supporting), "description": "Structural discoveries and execution notes are supporting evidence, not vulnerability conclusions."},
        "limitations": _limitations(findings, evidence_summary, engagement.status) +
            ([f"Report assembly reached its bounded load limit for {', '.join(capped)}; counts and appendices may be partial. Use the paginated Evidence explorer to inspect the remaining original records."] if capped else []),
        "data_limits": {"possibly_partial": bool(capped), "collections": capped},
        "execution_summary": evidence_summary,
        "remediation_plan": [
            {"priority": g["severity"], "finding_ids": [f["id"] for f in g["findings"]],
             "actions": list(dict.fromkeys(f["remediation_hint"] for f in g["findings"]))}
            for g in data["findings_by_severity"] if g["severity"] not in ("none", "info")
        ],
        "totals": {"findings": real_findings, "by_severity": sev_counts},
    }


def _overall_risk(sev_counts: dict[str, int]) -> str:
    for sev in ("critical", "high", "medium", "low"):
        if sev_counts.get(sev, 0) > 0:
            return sev
    return "none"


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
        f"This report summarizes the recorded assessment evidence for {engagement.target}. "
        f"The inventory contains {counts['subdomains']} subdomain record(s), {counts['hosts']} host/IP record(s), "
        f"{appendix_count(appendix, 'services')} port/service record(s), and "
        f"{tech_n} technology record(s). These counts are discoveries, not proof of vulnerability or complete coverage."
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
            f"The highest recorded technical severity is {_RISK_LABEL[overall_risk] if overall_risk != 'none' else 'not assessed'}. "
            "Severity and confidence are reported separately; business impact requires the system owner's review."
        )
    else:
        parts.append("No confirmed vulnerabilities were concluded during this assessment window.")

    return {
        "overall_risk": overall_risk,
        "overall_risk_label": _RISK_LABEL[overall_risk] if overall_risk != "none" else "Not assessed",
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


def _methodology(observations: list[Observation], executed_tools=()) -> list[dict[str, Any]]:
    tools_seen: dict[str, int] = defaultdict(int)
    for tool in executed_tools:
        tools_seen[tool] += 1
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


def _recon_appendix(observations: list[Observation], legacy=(), nodes=()) -> list[dict[str, Any]]:
    by_type: dict[str, list[Observation]] = defaultdict(list)
    for o in observations:
        by_type[o.type.value].append(o)

    raw_items = []
    for key, label, types in _APPENDIX_SECTIONS:
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for t in types:
            for o in by_type.get(t, []):
                value = _obs_value(o)
                _merge_inventory_item(unique, (t, value.lower()), {
                    "type": t,
                    "value": value,
                    "target": o.target,
                    "detail": _obs_detail(o),
                    "source_tool": o.source_tool,
                    "observation_id": o.id,
                })
        # Older engagements stored discovery facts as findings. Retain those
        # assets in the inventory even when no Observation row exists yet.
        for f in legacy:
            t = f.finding_type.value
            if t not in types:
                continue
            value = f.title if t in ("port", "service", "technology", "dns_record") else (f.target or f.title)
            if t in ("domain", "subdomain", "host", "ip"):
                value = str((f.metadata or {}).get("hostname") or (f.metadata or {}).get("ip") or
                            (f.title if _hostname(f.title) else value))
            _merge_inventory_item(unique, (t, value.lower()), {"type": t, "value": value, "target": f.target,
                "detail": f.description, "source_tool": f.source_tool, "finding_id": f.id})
        for node in nodes:
            t = node.asset_type.value
            if t not in types:
                continue
            _merge_inventory_item(unique, (t, node.label.lower()), {"type": t, "value": node.label,
                "target": node.label, "detail": "", "source_tool": ", ".join(node.source_tools or []), "asset_id": node.id})
        raw_items.extend(unique.values())

    normalized: dict[tuple[str, str], dict[str, Any]] = {}
    review = []
    for item in raw_items:
        t = item["type"]
        if t not in ("domain", "subdomain", "host", "ip"):
            _merge_inventory_item(normalized, (t, item["value"]), item)
            continue
        values = [part.strip().rstrip(".") for part in item["value"].split(",")]
        if not all(_hostname(value) for value in values):
            review.append(item)
            continue
        for value in values:
            try:
                ipaddress.ip_address(value)
                kind = "ip"
            except ValueError:
                kind = t
            _merge_inventory_item(normalized, (kind, value.lower()), {**item, "type": kind, "value": value})

    sections = []
    for key, label, types in _APPENDIX_SECTIONS:
        items = [item for item in normalized.values() if item["type"] in types]
        if items:
            items.sort(key=lambda x: (x["type"], x["value"]))
            sections.append({"key": key, "label": label, "count": len(items), "items": items})
    if review:
        sections.append({"key": "review", "label": "Unclassified discoveries", "count": len(review), "items": review})
    return sections


def _merge_inventory_item(bucket, key, item):
    """Compact the display row, never the routes back to its original records."""
    refs = list(item.get("record_refs", []))
    for field, kind in (("observation_id", "observation"), ("finding_id", "finding"), ("asset_id", "asset")):
        if item.get(field):
            ref = {"kind": kind, "id": item[field]}
            if ref not in refs:
                refs.append(ref)
    item = {**item, "record_refs": refs}
    if key not in bucket:
        bucket[key] = item
        return
    previous = bucket[key]
    for ref in refs:
        if ref not in previous["record_refs"]:
            previous["record_refs"].append(ref)
    sources = list(dict.fromkeys(filter(None, (previous.get("source_tool", "") + ", " + item.get("source_tool", "")).split(", "))))
    previous["source_tool"] = ", ".join(sources)
    if not previous.get("detail"):
        previous["detail"] = item.get("detail", "")


def _hostname(value: str) -> bool:
    """Presentation-only shape check; never promotes or discards stored evidence."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9_*](?:[a-zA-Z0-9_*-]{0,61}[a-zA-Z0-9_*])?\.)+[a-zA-Z][a-zA-Z0-9-]{0,62}\.?", value))


def _execution_summary(eid: str) -> dict[str, Any]:
    from sqlalchemy import select
    from osprey.db.session import SessionLocal
    from osprey.models.evidence import EvidenceRow

    with SessionLocal() as db:
        rows = db.execute(select(EvidenceRow.tool_name, EvidenceRow.exit_code, EvidenceRow.created_at)
                          .where(EvidenceRow.engagement_id == eid)).all()
    return {"runs": len(rows), "failed": sum(r.exit_code != 0 for r in rows),
            "tools": sorted({r.tool_name for r in rows if r.tool_name}),
            "first_run": min((r.created_at for r in rows), default=None),
            "last_run": max((r.created_at for r in rows), default=None)}


def _limitations(findings, execution, status) -> list[str]:
    limitations = [
        "This report is a point-in-time record of the available evidence; untested assets and controls may contain additional issues.",
        "Technical severity is an input to risk management, not a GRC certification or a complete assessment of business risk.",
    ]
    if status not in ("completed", "complete", "closed"):
        limitations.append("The engagement is not marked complete. Treat this report as a working draft.")
    if execution["failed"]:
        limitations.append(f"{execution['failed']} of {execution['runs']} recorded tool executions returned a non-zero exit code; affected checks may be incomplete.")
    unconfirmed = sum(str(f.confidence) != "confirmed" for f in findings)
    if unconfirmed:
        limitations.append(f"{unconfirmed} security conclusions are not confirmed and require further validation.")
    if not findings:
        limitations.append("No security conclusions have been filed. This does not establish the absence of vulnerabilities.")
    return limitations


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
        port = str(d.get("port") or "")
        host = f"{o.target}:{port}" if port else o.target
        return f"{name} @ {host}".strip(" @") if name else host
    if t == "technology":
        return str(d.get("name") or d.get("technology") or d.get("product") or o.target)
    if t in ("subdomain", "host", "ip"):
        return str(d.get("hostname") or d.get("ip") or d.get("value") or o.target)
    if t == "credential":
        user = d.get("username") or d.get("email") or d.get("user") or ""
        secret = d.get("password") or d.get("secret") or d.get("value") or ""
        return f"{user}:{secret}" if user and secret else (str(user) or str(secret) or o.target)
    if t in ("email", "person", "phone", "secret"):
        return str(d.get("email") or d.get("name") or d.get("phone") or d.get("secret") or d.get("value") or o.target)
    if t in ("url", "endpoint", "content_path", "js_endpoint"):
        return str(d.get("url") or d.get("endpoint") or d.get("path") or d.get("value") or o.target)
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
    out.append(f"**Highest recorded technical severity:** {es['overall_risk_label']}  ")
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

    out.extend(["## Limitations & Validation Status", ""])
    for limitation in report.get("limitations", []):
        out.append(f"- {limitation}")
    out.extend(["", "## Remediation Priorities", ""])
    for group in report.get("remediation_plan", []):
        out.append(f"### {group['priority'].title()} — {len(group['finding_ids'])} findings")
        out.extend(f"- {action}" for action in group["actions"])
        out.append("")

    out.append("## Findings")
    out.append("")
    groups = report["findings_by_severity"]
    if not groups:
        out.append("_No security conclusions recorded. This does not establish absence of vulnerabilities._")
        out.append("")
    for g in groups:
        out.append(f"### {g['severity'].title()} ({g['count']})")
        out.append("")
        for f in g["findings"]:
            out.append(f"#### {f['title']} — {f['id']}")
            out.append("")
            out.append(f"- **Target:** `{f['target'] or '—'}`  ·  **Confidence:** {f['confidence']}  ·  **Source:** {f['source_tool'] or '—'}")
            if f.get("description"):
                out.append("")
                out.append(f["description"])
            if f.get("evidence_snippet"):
                out.append("")
                out.append("**Evidence:**")
                out.append("")
                fence = "`" * max(3, max((len(part) for part in re.findall(r'`+', f['evidence_snippet'])), default=0) + 1)
                out.append(fence)
                out.append(f["evidence_snippet"])
                out.append(fence)
            out.append("")
            out.append(f"**Remediation:** {f['remediation_hint']}")
            if not f.get("remediation_recorded"):
                out.append("_Remediation needs authoring and validation with the system owner._")
            if f.get("observation_ids"):
                out.append(f"**Observation references:** {', '.join(f['observation_ids'])}")
            out.append("")

    if report["scanner_claims"]:
        out.append("## Unverified Scanner Claims")
        out.append("")
        out.append("_Raw scanner matches, not confirmed findings — each requires verification._")
        out.append("")
        for c in report["scanner_claims"]:
            out.append(f"- `{c['source_tool']}` — {c['title']} ({c['target']}) · claimed: {c['scanner_claimed_severity']}")
        out.append("")

    if report.get("review_candidates"):
        out.extend(["## Legacy Records Requiring Review", "",
                    "_Severity-labelled structural facts or execution notes, excluded from security-conclusion totals. Review the original evidence before promoting any claim._", ""])
        for candidate in report["review_candidates"]:
            out.append(f"- `{candidate['id']}` — {candidate['title']} ({candidate['target']}) · recorded severity: {candidate['severity']}")
        out.append("")

    out.append("## Appendix — Attack Surface Inventory")
    out.append("")
    for sec in report["recon_appendix"]:
        out.append(f"### {sec['label']} ({sec['count']})")
        out.append("")
        out.append("| Value | Detail | Source |")
        out.append("| --- | --- | --- |")
        for it in sec["items"]:
            cells = [str(it.get(key) or "").replace("|", "\\|").replace("\n", " ").replace("\r", " ") for key in ("value", "detail", "source_tool")]
            out.append("| " + " | ".join(cells) + " |")
        out.append("")

    out.append("---")
    out.append("")
    out.append("_Generated by Osprey._")
    return "\n".join(out)
