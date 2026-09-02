from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from osprey.schemas.tools import ToolExecutionRequest, ToolExecutionResponse
from osprey.services.package_install import execute_install_request
from osprey.services.script_exec import execute_script_request
from osprey.services.shell_exec import execute_shell_request
from osprey.services.tool_execution import execute_tool_request

logger = logging.getLogger(__name__)
router = APIRouter()


def _as_failure(tool_name: str, exc: Exception) -> ToolExecutionResponse:
    """Turn an unexpected exception into a structured response instead of a bare 500.

    A raw 500 gives the LLM nothing to act on (FastAPI's default body is often
    just "Internal Server Error"). Returning a normal ToolExecutionResponse
    means the operator mirror shows the real reason, so the agent can adjust
    (smaller batch, different params) instead of treating the tool as dead.
    Deliberate HTTPException (404 unknown tool, 400 bad params) still
    propagates normally — only genuinely unexpected failures land here.
    """
    logger.exception("Unhandled error executing %s", tool_name)
    return ToolExecutionResponse(
        tool_name=tool_name,
        success=False,
        error=f"{type(exc).__name__}: {exc}"[:2000],
    )


@router.post(
    "/execute",
    response_model=ToolExecutionResponse,
    summary="Execute a tool via MCP server",
)
async def execute_tool(request: ToolExecutionRequest) -> ToolExecutionResponse:
    """Run tool through validate → execute → findings → hybrid hints."""
    try:
        return await execute_tool_request(request)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        return _as_failure(request.tool_name, exc)


class ShellExecRequest(BaseModel):
    command: str = Field(..., min_length=1, description="Bash command (raw bash -c in unrestricted mode; allowlisted argv when gated)")
    engagement_id: str | None = None
    run_id: str | None = None
    reason: str = ""
    timeout: int = Field(default=180, ge=30, le=900)
    record_findings: bool = True


@router.post(
    "/shell",
    response_model=ToolExecutionResponse,
    summary="Shell exec in Kali (raw bash by default)",
)
async def shell_exec(request: ShellExecRequest) -> ToolExecutionResponse:
    """Think→execute path: raw bash -c in unrestricted mode; allowlisted argv when gated."""
    try:
        return await execute_shell_request(
            command=request.command,
            engagement_id=request.engagement_id,
            run_id=request.run_id,
            reason=request.reason,
            timeout=request.timeout,
            record_findings=request.record_findings,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        tool_label = f"shell:{request.command.split()[0]}" if request.command.strip() else "shell"
        return _as_failure(tool_label, exc)


class ScriptExecRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Full script body (python/bash)")
    language: str = Field(default="python3", description="python3 | python | bash | sh")
    engagement_id: str | None = None
    run_id: str | None = None
    reason: str = ""
    filename: str = Field(default="", description="Optional relative name under engagement workspace")
    packages: str = Field(
        default="",
        description="Comma-separated pip packages to install --user before python scripts",
    )
    timeout: int = Field(default=300, ge=30, le=900)
    record_findings: bool = True


@router.post(
    "/script",
    response_model=ToolExecutionResponse,
    summary="Write+run adaptive script in Kali",
)
async def script_exec(request: ScriptExecRequest) -> ToolExecutionResponse:
    """Elite adaptability lane: LLM writes a script; platform runs it under the engagement."""
    try:
        return await execute_script_request(
            code=request.code,
            language=request.language,
            engagement_id=request.engagement_id,
            run_id=request.run_id,
            reason=request.reason,
            timeout=request.timeout,
            filename=request.filename,
            packages=request.packages,
            record_findings=request.record_findings,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        return _as_failure(f"script:{request.language}", exc)


class InstallRequest(BaseModel):
    manager: str = Field(default="pip", description="pip | apt")
    packages: str = Field(..., min_length=1, description="Comma-separated package names")
    engagement_id: str | None = None
    run_id: str | None = None
    reason: str = ""
    timeout: int = Field(default=300, ge=60, le=900)


@router.post(
    "/install",
    response_model=ToolExecutionResponse,
    summary="Gated pip/apt install in Kali for script deps",
)
async def install_packages(request: InstallRequest) -> ToolExecutionResponse:
    try:
        return await execute_install_request(
            manager=request.manager,
            packages=request.packages,
            engagement_id=request.engagement_id,
            run_id=request.run_id,
            reason=request.reason,
            timeout=request.timeout,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        return _as_failure(f"install:{request.manager}", exc)
