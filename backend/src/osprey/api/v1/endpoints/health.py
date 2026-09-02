from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="Read service health")
def read_health() -> dict[str, str]:
    return {"status": "ok", "service": "osprey-api"}


@router.get("/execution", summary="Report tool execution readiness (docker/native)")
def read_execution_status() -> dict:
    """Whether tools can actually run right now, and how (docker vs native).

    The /scan --engine preflight calls this so a down Kali container surfaces as
    one clear, actionable error instead of every tool reporting '(failed)'.
    """
    from osprey.services.mcp_client import get_mcp_client

    return get_mcp_client().execution_status()
