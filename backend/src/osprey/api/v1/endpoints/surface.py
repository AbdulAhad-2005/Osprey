"""Surface expansion API — the only HTTP-reachable entry point into the BFS
expansion engine. Thin wrapper; all logic lives in services/surface_expansion.py.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from osprey.services.investigation_director import run_to_completion
from osprey.services.surface_expansion import ExpansionReport

router = APIRouter()


class ExpandRequest(BaseModel):
    engagement_id: str
    run_id: str = ""
    # This endpoint is synchronous — it blocks the HTTP connection for the
    # whole run, unlike the job-queued path (job_store's EXPANSION kind,
    # what platform_expand/CLI --engine actually use, default max_passes=50,
    # no hard ceiling). Kept lower here and still capped for that reason —
    # a caller wanting genuinely exhaustive, long-running coverage should
    # use the job-queued path instead of holding a connection open for hours.
    max_passes: int = Field(default=5, ge=1, le=50)


@router.post("/expand", response_model=ExpansionReport)
async def expand(request: ExpandRequest) -> ExpansionReport:
    return await run_to_completion(
        engagement_id=request.engagement_id, run_id=request.run_id, max_passes=request.max_passes,
    )
