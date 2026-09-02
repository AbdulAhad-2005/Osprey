"""Findings API for Commander memory."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from osprey.platform.handoff import export_structured_findings
from osprey.schemas.agent_run import StructuredFindingsExport
from osprey.schemas.finding import (
    Finding,
    FindingListResponse,
    FindingType,
    GroupedFindingListResponse,
)
from osprey.services.engagement_graph import get_engagement_graph
from osprey.services.findings_store import get_findings_store
from osprey.services.target_utils import resolve_ipv4

router = APIRouter()


@router.get("/", response_model=FindingListResponse)
def list_findings(
    engagement_id: str | None = Query(default=None),
    run_id: str | None = Query(default=None),
    phase: str | None = Query(default=None),
    finding_type: str | None = Query(default=None),
    claim_severity: str | None = Query(default=None),
    evidence_grade: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    exclude_noise: bool = Query(
        default=True,
        description=(
            "Exclude OBSERVATION-type findings (unparsed/low-signal tool output, "
            "kept for evidence but not a real finding) unless finding_type is set "
            "explicitly. Set false to see everything, noise included."
        ),
    ),
) -> FindingListResponse:
    store = get_findings_store()
    # Accept "ip" as alias for "host"
    ft: FindingType | None = None
    if finding_type:
        raw = finding_type.strip().lower()
        if raw == "ip":
            ft = FindingType.HOST
        else:
            try:
                ft = FindingType(raw)
            except ValueError:
                from fastapi import HTTPException
                valid = ", ".join(str(t.value) for t in FindingType)
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid finding_type '{raw}'. Valid types: {valid}. Use 'ip' as alias for 'host'.",
                )
    findings = store.list(
        engagement_id=engagement_id,
        run_id=run_id,
        phase=phase,
        finding_type=ft,
        claim_severity=claim_severity,
        evidence_grade=evidence_grade,
        tag=tag,
        q=q,
        limit=limit,
        exclude_noise=exclude_noise,
    )
    return FindingListResponse(findings=findings, total=len(findings))


@router.get("/grouped", response_model=GroupedFindingListResponse)
def list_findings_grouped(
    engagement_id: str | None = Query(default=None),
    run_id: str | None = Query(default=None),
    phase: str | None = Query(default=None),
    finding_type: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=2000, ge=1, le=10000, description="How many raw findings to scan before grouping."),
    group_limit: int = Query(default=200, ge=1, le=1000),
    exclude_noise: bool = Query(default=True),
) -> GroupedFindingListResponse:
    """Same data as / , collapsed to one row per distinct issue pattern
    (e.g. one nmap NSE script firing on 8 ports of a host becomes one row
    listing 8 affected targets, not 8 near-identical rows) — worst severity
    and widest-affected first. Every individual finding still exists
    underneath; this is a display aggregation, nothing is discarded."""
    ft: FindingType | None = None
    if finding_type:
        raw = finding_type.strip().lower()
        ft = FindingType.HOST if raw == "ip" else FindingType(raw)
    groups, total_groups, total_findings = get_findings_store().list_grouped(
        engagement_id=engagement_id, run_id=run_id, phase=phase, finding_type=ft,
        tag=tag, q=q, limit=limit, exclude_noise=exclude_noise, group_limit=group_limit,
    )
    return GroupedFindingListResponse(groups=groups, total_groups=total_groups, total_findings=total_findings)


@router.get("/summary")
def findings_summary(
    engagement_id: str | None = Query(default=None),
    run_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Text summary for injection into Commander prompt."""
    return get_findings_store().structured_summary_meta(
        engagement_id=engagement_id,
        run_id=run_id,
    )


@router.get("/structured", response_model=StructuredFindingsExport)
def structured_findings(
    engagement_id: str | None = Query(default=None),
    run_id: str | None = Query(default=None),
    target: str = Query(default=""),
    from_phase: str | None = Query(default=None),
) -> StructuredFindingsExport:
    """Machine-readable findings export for phase handoff and Commander agents."""
    resolved = resolve_ipv4(target) if target else None
    return export_structured_findings(
        engagement_id=engagement_id or "",
        run_id=run_id or "",
        target=target,
        resolved_ip=resolved,
        from_phase=from_phase,
    )


@router.get("/handoff")
def handoff_dossier(
    engagement_id: str = Query(...),
    run_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Complete, self-contained engagement dossier for a zero-context downstream agent.

    The exploitation / post-exploitation agent (and the dashboard) can reconstruct
    the entire recon/enum/scanning picture from this one payload: asset inventory
    with attributes, credentials/secrets, vulnerabilities, entry points, every
    finding with provenance + evidence grade, and the relationship graph.
    """
    from osprey.services.handoff_dossier import build_handoff_dossier

    return build_handoff_dossier(engagement_id, run_id=run_id or "")


@router.get("/{finding_id}/occurrences")
def finding_occurrences(finding_id: str) -> dict[str, Any]:
    """Full provenance for a canonical finding — every tool/run that observed it.

    Downstream consumers (exploit agent, dashboard) use this to see how strongly a
    fact is supported and by which tools, without the recon phase having lost any
    provenance to de-duplication.
    """
    store = get_findings_store()
    return {
        "finding_id": finding_id,
        "recurrence": store.recurrence(finding_id=finding_id),
        "occurrences": store.occurrences(finding_id=finding_id),
    }


@router.post("/", response_model=Finding)
def create_finding(finding: Finding) -> Finding:
    stored = get_findings_store().add(finding)
    get_engagement_graph().ingest_finding(stored)
    return stored


@router.post("/bulk", response_model=FindingListResponse)
def create_findings_bulk(findings: list[Finding]) -> FindingListResponse:
    """Persist many operator-authored findings in one call.

    Lets the LLM store everything it noticed in a single raw-output read
    (paths, cookie domains, IP clusters, version banners) instead of one
    round-trip per fact. Reuses the same dedup + graph ingest as single
    writes, so counters and the engagement graph stay consistent.
    """
    if not findings:
        return FindingListResponse(findings=[], total=0)
    store = get_findings_store()
    stored = store.add_many(findings)
    if stored:
        get_engagement_graph().ingest_many(stored)
    return FindingListResponse(findings=stored, total=len(stored))
