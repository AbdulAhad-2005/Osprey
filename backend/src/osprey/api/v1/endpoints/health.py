from fastapi import APIRouter, Response, status

from osprey.services.startup_readiness import snapshot

router = APIRouter()


@router.get("/", summary="Read service health")
def read_health(response: Response) -> dict[str, object]:
    payload = snapshot("osprey-api")
    if not payload["ready"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


@router.get("/execution", summary="Report tool execution readiness (docker/native)")
def read_execution_status() -> dict:
    """Whether tools can actually run right now, and how (docker vs native).

    The /scan --engine preflight calls this so a down Kali container surfaces as
    one clear, actionable error instead of every tool reporting '(failed)'.
    """
    from osprey.services.mcp_client import get_mcp_client

    return get_mcp_client().execution_status()
