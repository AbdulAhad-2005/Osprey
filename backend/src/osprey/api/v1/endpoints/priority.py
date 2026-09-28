"""Priority API — plans/harness/06-prioritization-engine.md.

What's worth doing next over the world model (observations, assets,
questions, attack paths) — a different question from a Finding's confidence
(Plan 03's one law), never feeding back into it.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from osprey.schemas.priority import PriorityListResponse
from osprey.services import priority

router = APIRouter()

_ALL_KINDS = ("observation", "asset", "question", "attack_path")


@router.get("/top", response_model=PriorityListResponse)
def list_top_priorities(
    engagement_id: str = Query(...),
    kinds: str = Query(default="observation,asset,question,attack_path"),
    limit: int = Query(default=20, ge=1, le=200),
) -> PriorityListResponse:
    kind_tuple = tuple(k.strip() for k in kinds.split(",") if k.strip()) or _ALL_KINDS
    items = priority.top_priorities(engagement_id, kinds=kind_tuple, limit=limit)
    return PriorityListResponse(items=items, total=len(items))


@router.get("/phase/{phase}")
def get_phase_priority(phase: str, engagement_id: str = Query(...)) -> dict[str, Any]:
    ctx = priority.build_context(engagement_id)
    score, reason = priority.phase_priority(engagement_id, phase, ctx=ctx)
    unlocked, gate_reason = priority.should_unlock_phase(engagement_id, phase, ctx=ctx)
    return {"phase": phase, "score": score, "reason": reason, "unlocked": unlocked, "gate_reason": gate_reason}


@router.get("/anomalies")
def get_anomalies(engagement_id: str = Query(...)) -> dict[str, Any]:
    """plans/harness/14-pentester-intelligence.md — on-demand peer-anomaly
    check ("what looks weird right now"). The same detector already runs
    ambiently after every recon pass (investigation_director.py); this is
    for a caller who wants a fresh read immediately rather than waiting for
    the next pass."""
    from osprey.services.anomaly_detection import detect_peer_anomalies

    observations = detect_peer_anomalies(engagement_id)
    return {
        "engagement_id": engagement_id,
        "count": len(observations),
        "anomalies": [
            {
                "target": o.target,
                "kind": o.details.get("kind"),
                "title": o.details.get("title"),
                "details": o.details,
            }
            for o in observations
        ],
    }
