from fastapi import APIRouter

from osprey.api.v1.endpoints import (
    agent,
    audit,
    capabilities,
    config,
    engagements,
    exploit_queue,
    findings,
    health,
    hybrid,
    jobs,
    mcp,
    models,
    pipeline,
    surface,
    tools,
)

api_v1_router = APIRouter()
api_v1_router.include_router(health.router, prefix="/health", tags=["health"])
api_v1_router.include_router(agent.router, prefix="/agent", tags=["agent"])
api_v1_router.include_router(tools.router, prefix="/tools", tags=["tools"])
api_v1_router.include_router(capabilities.router, prefix="/capabilities", tags=["capabilities"])
api_v1_router.include_router(hybrid.router, prefix="/hybrid", tags=["hybrid"])
api_v1_router.include_router(mcp.router, prefix="/mcp", tags=["mcp"])
api_v1_router.include_router(jobs.router, prefix="/jobs", tags=["jobs"])
api_v1_router.include_router(findings.router, prefix="/findings", tags=["findings"])
api_v1_router.include_router(exploit_queue.router, prefix="/exploit-queue", tags=["exploit-queue"])
api_v1_router.include_router(surface.router, prefix="/surface", tags=["surface"])
api_v1_router.include_router(pipeline.router, prefix="/pipeline", tags=["pipeline"])
api_v1_router.include_router(models.router, prefix="/models", tags=["models"])
api_v1_router.include_router(config.router, prefix="/config", tags=["config"])
api_v1_router.include_router(engagements.router, prefix="/engagements", tags=["engagements"])
api_v1_router.include_router(audit.router, prefix="/audit", tags=["audit"])
