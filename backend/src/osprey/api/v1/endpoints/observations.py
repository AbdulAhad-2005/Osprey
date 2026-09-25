"""Observations API — read access for the earned-finding pipeline
(plans/harness/03-earned-finding-pipeline.md). Without this, ``platform_file_finding``
has no way to discover the observation_ids it requires; this is the missing
half of that capability, not a new feature.

Write access (POST /) is narrow and deliberate: it exists ONLY for an
LLM/operator to record a structural fact they reasoned out or hand-verified
that no parser produced (``extracted_by=llm|human``, never ``parser`` —
parsers write via the ingest pipeline, not this endpoint). This is what
closes the disclosed gap in ``platform_record_finding``/``platform_record_
findings``: they used to construct a Finding directly with a caller-asserted
confidence, bypassing ``confidence_for`` (Plan 03's one law). Now they record
an Observation here first, then call ``file_finding`` with
``evidence_kind=attestation`` — confidence is still computed, never asserted;
only WHAT was observed is caller-supplied, same as any other Observation.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from osprey.schemas.observation import Observation, ObservationListResponse, ObservationSource, ObservationType
from osprey.services.observation_store import get_observation_store

router = APIRouter()


class RecordObservationRequest(BaseModel):
    engagement_id: str = Field(..., min_length=1)
    type: str = Field(default="raw")
    target: str = ""
    details: dict = Field(default_factory=dict)
    source_tool: str = "operator_record"
    tags: list[str] = Field(default_factory=list)
    run_id: str = ""
    extracted_by: str = Field(default="llm", description="llm|human — never parser (that path is the ingest pipeline)")


@router.get("/", response_model=ObservationListResponse)
def list_observations(
    engagement_id: str = Query(...),
    type: str | None = Query(default=None),
    target: str | None = Query(default=None),
    limit: int = Query(default=200, le=2000),
) -> ObservationListResponse:
    store = get_observation_store()
    if target:
        items = store.list_by_target(engagement_id, target, limit=limit)
    elif type:
        try:
            otype = ObservationType(type.strip().lower())
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Unknown observation type: {type!r}")
        items = store.list_by_type(engagement_id, otype, limit=limit)
    else:
        items = store.list_for_engagement(engagement_id, limit=limit)
    return ObservationListResponse(observations=items, total=len(items))


@router.get("/{observation_id}", response_model=Observation)
def get_observation(observation_id: str) -> Observation:
    obs = get_observation_store().get(observation_id)
    if obs is None:
        raise HTTPException(status_code=404, detail="Observation not found")
    return obs


@router.post("/", response_model=Observation)
def record_observation(request: RecordObservationRequest) -> Observation:
    try:
        otype = ObservationType(request.type.strip().lower())
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Unknown observation type: {request.type!r}")
    extracted_by = request.extracted_by.strip().lower()
    if extracted_by not in ("llm", "human"):
        raise HTTPException(status_code=422, detail="extracted_by must be llm or human")

    observation = Observation(
        engagement_id=request.engagement_id,
        run_id=request.run_id,
        type=otype,
        target=request.target,
        details=request.details,
        source_tool=request.source_tool or "operator_record",
        tags=request.tags,
        extracted_by=ObservationSource(extracted_by),
    )
    return get_observation_store().record(observation)
