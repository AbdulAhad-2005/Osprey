"""Revisioned, harness-driven investigation step API."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query

from osprey.schemas.investigation import (
    InvestigationDecision,
    InvestigationStep,
    InvestigationStepRequest,
)
from osprey.schemas.jobs import JobKind, JobStartRequest
from osprey.services.investigation_capabilities import diagnose_revision_mismatch, list_step
from osprey.services.job_store import get_job_store

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/step", response_model=InvestigationStep)
def get_step(
    engagement_id: str = Query(..., min_length=1),
    run_id: str = Query(default=""),
) -> InvestigationStep:
    return list_step(engagement_id, run_id)


@router.post("/step", response_model=InvestigationDecision, status_code=202)
async def start_step(request: InvestigationStepRequest) -> InvestigationDecision:
    current = list_step(request.engagement_id, request.run_id)
    if current.revision != request.expected_revision:
        diff = diagnose_revision_mismatch(
            request.engagement_id, request.expected_revision, current.revision
        )
        logger.warning(
            "stale investigation revision engagement=%s opportunity=%s: %s",
            request.engagement_id, request.opportunity_id, diff,
        )
        raise HTTPException(
            status_code=409,
            detail={
                "error": "stale_investigation_revision",
                "expected_revision": request.expected_revision,
                "current_revision": current.revision,
                "diff": diff,
            },
        )
    opportunity = next((item for item in current.opportunities if item.id == request.opportunity_id), None)
    if opportunity is None:
        raise HTTPException(
            status_code=409,
            detail={"error": "opportunity_not_current", "current_revision": current.revision},
        )

    try:
        job = get_job_store().create_and_spawn(JobStartRequest(
            kind=JobKind.INVESTIGATION_STEP,
            engagement_id=request.engagement_id,
            run_id=request.run_id,
            label=(
                f"{opportunity.tool}: {len(opportunity.subjects)} subject(s)" if opportunity.tool
                else f"{opportunity.capability.value}: {len(opportunity.subjects)} subject(s)"
            ),
            opportunity_id=opportunity.id,
            capability=opportunity.capability.value,
            subject_ids=[subject.asset_id for subject in opportunity.subjects],
            capability_input=dict(opportunity.evidence),
            tool=opportunity.tool,
            params=dict(opportunity.params),
            additional_args=opportunity.additional_args,
            timeout=opportunity.timeout or 300,
            expected_revision=request.expected_revision,
            driver=request.driver,
            rationale=request.rationale,
        ))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return InvestigationDecision(
        accepted=True,
        decision="bounded capability job started",
        revision=current.revision,
        opportunity=opportunity,
        job=job,
    )
