"""Generic phase-to-phase handoff from structured findings."""

from __future__ import annotations

import re

from osprey.schemas.agent_run import PhaseHandoff, StructuredFindingsExport
from osprey.schemas.finding import FindingType
from osprey.services.findings_store import get_findings_store

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def export_structured_findings(
    *,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
    resolved_ip: str | None = None,
    from_phase: str | None = None,
) -> StructuredFindingsExport:
    store = get_findings_store()
    findings = store.list(
        engagement_id=engagement_id or None,
        run_id=run_id or None,
        phase=from_phase,
        limit=500,
    )
    if not findings and from_phase:
        findings = store.list(engagement_id=engagement_id or None, run_id=run_id or None, limit=500)

    by_type: dict[str, list[str]] = {}
    technologies: list[str] = []

    for finding in findings:
        key = finding.finding_type.value
        by_type.setdefault(key, [])
        if finding.title not in by_type[key]:
            by_type[key].append(finding.title)
        tech = finding.metadata.get("technology")
        if isinstance(tech, str) and tech and tech not in technologies:
            technologies.append(tech)

    primary = _derive_primary_targets(
        by_type=by_type,
        target=target,
        resolved_ip=resolved_ip,
        findings=findings,
    )

    return StructuredFindingsExport(
        target=target,
        resolved_ip=resolved_ip,
        engagement_id=engagement_id,
        run_id=run_id,
        findings_by_type=by_type,
        primary_targets=primary,
        technologies=technologies,
        text_summary=store.structured_summary_for_agent(
            engagement_id=engagement_id or None,
            run_id=run_id or None,
        ),
        total_findings=len(findings),
    )


def build_phase_handoff(
    *,
    from_phase: str,
    to_phase: str,
    engagement_id: str = "",
    run_id: str = "",
    target: str = "",
    resolved_ip: str | None = None,
) -> PhaseHandoff:
    exported = export_structured_findings(
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
        resolved_ip=resolved_ip,
        from_phase=from_phase,
    )
    return PhaseHandoff(
        from_phase=from_phase,
        to_phase=to_phase,
        target=target,
        resolved_ip=resolved_ip,
        primary_targets=exported.primary_targets,
        findings_by_type=exported.findings_by_type,
        technologies=exported.technologies,
        text_summary=exported.text_summary,
        metadata={
            "engagement_id": engagement_id,
            "run_id": run_id,
            "total_findings": exported.total_findings,
        },
    )


def handoff_to_prompt(packet: PhaseHandoff) -> str:
    lines = [
        f"PHASE HANDOFF: {packet.from_phase} → {packet.to_phase}",
        f"TARGET: {packet.target}",
    ]
    if packet.resolved_ip:
        lines.append(f"RESOLVED_IP: {packet.resolved_ip}")
    if packet.primary_targets:
        lines.append(f"PRIMARY TARGETS: {', '.join(packet.primary_targets[:30])}")
    if packet.findings_by_type:
        lines.append("FINDINGS BY TYPE:")
        for ftype, items in packet.findings_by_type.items():
            sample = ", ".join(items[:15])
            extra = f" (+{len(items) - 15})" if len(items) > 15 else ""
            lines.append(f"  - {ftype}: {sample}{extra}")
    if packet.text_summary and not packet.text_summary.startswith("No findings"):
        lines.append(f"SUMMARY:\n{packet.text_summary[:1200]}")
    lines.append(
        "Use the above as ground truth. Do not repeat completed work unless there is a clear gap."
    )
    return "\n".join(lines)


def _derive_primary_targets(
    *,
    by_type: dict[str, list[str]],
    target: str,
    resolved_ip: str | None,
    findings: list,
) -> list[str]:
    candidates: list[str] = []

    if target:
        candidates.append(target)
    if resolved_ip:
        candidates.append(resolved_ip)

    for url in by_type.get(FindingType.URL.value, []):
        candidates.append(url)

    for host in by_type.get(FindingType.HOST.value, []):
        candidates.append(host)

    for sub in by_type.get(FindingType.SUBDOMAIN.value, []):
        candidates.append(sub)

    for finding in findings:
        if finding.target:
            candidates.append(str(finding.target))
        for ip in _IP_RE.findall(finding.evidence or ""):
            candidates.append(ip)
        for ip in _IP_RE.findall(finding.title or ""):
            candidates.append(ip)

    return list(dict.fromkeys(c for c in candidates if c))
