"""Context-dependent situational brief — what we know, what's missing, what to do next."""

from __future__ import annotations

import re

from osprey.platform.run_context import RunAssistState
from osprey.schemas.finding import FindingType
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.findings_store import get_findings_store

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SMB_TOOLS = frozenset(
    {"enum4linux_scan", "enum4linux_ng_advanced", "smbmap_scan", "netexec_scan", "nbtscan_netbios"}
)


def build_situational_brief(
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
    resolved_ip: str | None = None,
    phase: str = "full",
    assist_state: RunAssistState | None = None,
    user_goal: str = "",
) -> str:
    """Summarize evidence so the LLM picks the next purposeful step — not every catalog tool."""
    state = assist_state or RunAssistState()
    findings = get_findings_store().list(
        engagement_id=engagement_id or None,
        run_id=run_id or None,
        limit=500,
    )
    graph = get_engagement_graph().summary(engagement_id=engagement_id, run_id=run_id)

    by_type: dict[str, int] = {}
    for finding in findings:
        key = finding.finding_type.value
        by_type[key] = by_type.get(key, 0) + 1

    subdomains = by_type.get(FindingType.SUBDOMAIN.value, 0)
    urls = by_type.get(FindingType.URL.value, 0)
    ports = by_type.get(FindingType.PORT.value, 0)
    services = by_type.get(FindingType.SERVICE.value, 0)
    hosts = by_type.get(FindingType.HOST.value, 0)

    target_is_ip = bool(target and _IP_RE.fullmatch(target.strip()))
    primary_ip = resolved_ip or (target if target_is_ip else "")

    known: list[str] = []
    gaps: list[str] = []
    skip: list[str] = []
    next_steps: list[str] = []

    if target:
        known.append(f"Primary target: {target}")
    if resolved_ip and resolved_ip != target:
        known.append(f"Resolved IP: {resolved_ip}")
    if subdomains:
        known.append(f"{subdomains} subdomain(s) in findings")
    if urls:
        known.append(f"{urls} live URL(s)")
    if services:
        known.append(f"{services} service(s) identified")
    elif ports:
        known.append(f"{ports} open port(s)")
    if hosts:
        known.append(f"{hosts} host record(s)")

    if state.successful_tools:
        sample = ", ".join(sorted(state.successful_tools)[:8])
        extra = f" (+{len(state.successful_tools) - 8})" if len(state.successful_tools) > 8 else ""
        known.append(f"Tools that already produced useful output: {sample}{extra}")

    # --- Gaps (what the picture is still missing) ---
    if not findings:
        if target_is_ip:
            gaps.append("No enumeration results yet on this IP")
            next_steps.append(
                "Start with a focused TCP port scan on the IP, then deepen only on open services"
            )
        else:
            gaps.append("No asset discovery yet for this domain")
            next_steps.append(
                "Discover attack surface (subdomains/DNS), then probe what is live — one layer at a time"
            )
    else:
        if not target_is_ip and subdomains == 0 and urls == 0:
            gaps.append("Domain target but no subdomains or live URLs yet")
            next_steps.append("Enumerate subdomains or confirm apex/live hosts before network-heavy scans")

        if urls > 0 and ports == 0 and services == 0 and primary_ip:
            gaps.append("Live web hosts but no port/service map on the IP yet")
            next_steps.append(f"Port scan {primary_ip} — use ports from evidence if any, else top common ports")

        if ports > 0 and services == 0:
            gaps.append("Open ports without service/version detail")
            next_steps.append("Run service/version detection on known open ports only")

        if subdomains >= 3 and ports == 0 and primary_ip:
            gaps.append("Subdomains discovered but IP not port-scanned")
            next_steps.append(f"Scan {primary_ip} before running SMB or niche protocol tools")

    open_445 = any("445" in p for p in graph.open_ports) or _has_port(findings, "445")
    open_139 = any("139" in p for p in graph.open_ports) or _has_port(findings, "139")
    if not open_445 and not open_139:
        skip.append("SMB/NetBIOS tools — no 139/445 in evidence (typical on Linux-only targets)")

    if "smb" in state.skip_categories:
        skip.append("SMB enumeration — prior attempts showed no Windows file sharing")

    for tool in sorted(state.successful_tools):
        if tool in _SMB_TOOLS and not open_445 and not open_139:
            continue
        skip.append(f"Do not re-run {tool} unless scope changed — output already captured")

    failed_tools = [
        name for name, count in state.tools_attempted.items() if name not in state.successful_tools
    ]
    if failed_tools:
        sample = ", ".join(failed_tools[:6])
        skip.append(f"Failed without useful output (change approach before retry): {sample}")

    for pivot in graph.pivot_hints[:2]:
        if pivot not in next_steps:
            next_steps.append(pivot)

    if not next_steps and findings:
        next_steps.append(
            "Review SESSION FINDINGS — deepen only where evidence supports it, then summarize for the user"
        )

    lines = ["CURRENT SITUATION (read this before choosing a tool):"]
    if user_goal.strip():
        lines.append(f"USER GOAL: {user_goal.strip()[:300]}")

    if known:
        lines.append("WHAT WE ALREADY KNOW:")
        lines.extend(f"  - {item}" for item in known)
    else:
        lines.append("WHAT WE ALREADY KNOW: nothing yet — pick one high-value first step")

    if gaps:
        lines.append("WHAT IS STILL MISSING:")
        lines.extend(f"  - {item}" for item in gaps[:5])

    if skip:
        lines.append("LIKELY NOT WORTH DOING NOW:")
        lines.extend(f"  - {item}" for item in skip[:6])

    if next_steps:
        lines.append("SENSIBLE NEXT MOVES (pick one, not the whole catalog):")
        for step in next_steps[:3]:
            lines.append(f"  → {step}")

    lines.append(
        "Do not run tools just because they exist in the catalog. "
        "Each step should close a specific gap above or follow directly from the last tool output."
    )
    return "\n".join(lines)


def _has_port(findings: list, port: str) -> bool:
    for finding in findings:
        if finding.finding_type not in (FindingType.PORT, FindingType.SERVICE):
            continue
        if port in finding.title or str(finding.metadata.get("port", "")) == port:
            return True
    return False
