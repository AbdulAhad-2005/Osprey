"""Context packet API — plans/harness/07-context-packet.md."""

from __future__ import annotations

from fastapi import APIRouter, Query

from osprey.services.context_packet import build_context_packet

router = APIRouter()


@router.get("/packet")
def get_context_packet(engagement_id: str = Query(...)) -> dict[str, str]:
    return {"packet": build_context_packet(engagement_id)}
