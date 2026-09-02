from __future__ import annotations

from fastapi import APIRouter, Query

from osprey.schemas.audit import AuditLogEntry
from osprey.services.audit_log import get_audit_log

router = APIRouter()


@router.get(
    "/",
    response_model=list[AuditLogEntry],
    summary="Query audit log entries",
)
def list_audit_entries(
    engagement_id: str | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[AuditLogEntry]:
    return get_audit_log().query(
        engagement_id=engagement_id,
        tool_name=tool_name,
        limit=limit,
    )
