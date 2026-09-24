"""Observations API — read access for the earned-finding pipeline
(plans/harness/03-earned-finding-pipeline.md). Without this, ``platform_file_finding``
has no way to discover the observation_ids it requires; this is the missing
half of that capability, not a new feature."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from osprey.schemas.observation import Observation, ObservationListResponse, ObservationType
from osprey.services.observation_store import get_observation_store

router = APIRouter()


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
