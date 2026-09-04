"""Capabilities API — tool/task catalog for the Commander LLM layer."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from osprey.schemas.tool_call import ToolCallProposal, ToolCallValidationResult
from osprey.schemas.tool_capability import PhaseCapabilitiesResponse, ToolCapability
from osprey.services.command_builder import build_command_for_tool
from osprey.services.param_validator import validate_tool_call
from osprey.services.skills_loader import load_shared_context, load_skill_for_task, load_skills_for_phase
from osprey.services.task_registry import (
    get_phase_capabilities,
    get_tool_capability,
    get_tools_for_task,
    list_tasks,
    list_tool_capabilities,
    llm_tool_catalog_for_phase,
)

router = APIRouter()


@router.get("/phases/{phase}", response_model=PhaseCapabilitiesResponse)
def phase_capabilities(phase: str) -> PhaseCapabilitiesResponse:
    if phase not in ("recon", "network"):
        raise HTTPException(404, detail="Phase must be recon or network")
    return get_phase_capabilities(phase)


@router.get("/phases/{phase}/llm-catalog")
def llm_catalog(phase: str) -> dict:
    """Compact catalog for LiteLLM / function-calling setup."""
    if phase not in ("recon", "network"):
        raise HTTPException(404, detail="Phase must be recon or network")
    return llm_tool_catalog_for_phase(phase)


@router.get("/tasks")
def tasks(phase: str | None = Query(default=None)) -> list[dict]:
    return [t.model_dump() for t in list_tasks(phase=phase)]


@router.get("/tasks/{task_id}/tools", response_model=list[ToolCapability])
def tools_for_task(task_id: str) -> list[ToolCapability]:
    tools = get_tools_for_task(task_id)
    if not tools:
        raise HTTPException(404, detail=f"Unknown task: {task_id}")
    return tools


@router.get("/tools/{tool_name}", response_model=ToolCapability)
def tool_capability(tool_name: str) -> ToolCapability:
    cap = get_tool_capability(tool_name)
    if cap is None:
        raise HTTPException(404, detail=f"Unknown tool: {tool_name}")
    return cap


@router.get("/tools", response_model=list[ToolCapability])
def all_tools(
    phase: str | None = Query(default=None),
    task_id: str | None = Query(default=None),
) -> list[ToolCapability]:
    return list_tool_capabilities(phase=phase, task_id=task_id)


@router.get("/skills/{phase}")
def skills_for_phase(phase: str) -> dict[str, str]:
    """Full skill text for any phase (recon/network/web/vuln/exploit/osint/…).

    Not restricted to a fixed phase list — the platform spans every phase now, and
    a missing phase dir simply yields the always-relevant shared methodology.
    """
    if phase == "shared":
        return {"content": load_shared_context()}
    return {"content": load_skills_for_phase(phase, allow_missing=True)}


@router.get("/skills-index")
def skills_index(
    phase: str = Query(default=""),
    query: str = Query(default=""),
) -> dict:
    """Browse all skills (name, description, phase, tags). Use /skills-file for full text."""
    from osprey.services.knowledge_browser import list_skills

    items = list_skills(phase=phase, query=query)
    return {"count": len(items), "skills": items}


@router.get("/skills-file")
def skills_file(path: str = Query(..., min_length=1)) -> dict:
    """Fetch one skill markdown by relative path (e.g. shared/evidence-to-hypothesis.md)."""
    from osprey.services.knowledge_browser import get_skill

    skill = get_skill(path)
    if skill is None:
        raise HTTPException(404, detail=f"Skill not found: {path}")
    return skill


@router.get("/config-index")
def config_index() -> dict:
    from osprey.services.knowledge_browser import list_configs

    items = list_configs()
    return {"count": len(items), "configs": items}


@router.get("/config-file")
def config_file(name: str = Query(..., min_length=1)) -> dict:
    from osprey.services.knowledge_browser import get_config

    cfg = get_config(name)
    if cfg is None:
        raise HTTPException(404, detail=f"Config not found or not allowlisted: {name}")
    return cfg


@router.get("/skills/task/{task_id}")
def skills_for_task(task_id: str) -> dict[str, str]:
    content = load_skill_for_task(task_id)
    if not content:
        raise HTTPException(404, detail=f"No skill for task: {task_id}")
    return {"content": content}


@router.post("/validate", response_model=ToolCallValidationResult)
def validate_proposal(proposal: ToolCallProposal) -> ToolCallValidationResult:
    """Validate LLM tool proposal before execution (permissive flags)."""
    return validate_tool_call(proposal)


class ProposeSkillRequest(BaseModel):
    name: str
    phase: str
    description: str
    content: str
    tags: list[str] = Field(default_factory=list)
    engagement_id: str = ""
    evidence: str = ""


@router.post("/learned-skills/propose")
def propose_learned_skill(req: ProposeSkillRequest) -> dict:
    """Propose a new operator-local learned skill (inert until approved).

    Gated by `enable_learned_skills`. Validates shape and rejects anything too
    similar to an existing skill — a learned skill must be a genuinely new
    technique, not a merge/restatement of the shipped library.
    """
    from osprey.core.config import get_settings
    from osprey.services.learned_skills import LearnedSkillError, propose_skill

    if not get_settings().enable_learned_skills:
        raise HTTPException(403, detail="Learned skills are disabled (set enable_learned_skills=true).")
    try:
        prop = propose_skill(
            name=req.name, phase=req.phase, description=req.description,
            content=req.content, tags=req.tags, engagement_id=req.engagement_id,
            evidence=req.evidence,
        )
    except LearnedSkillError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    return {"status": "proposed", "id": prop["id"], "slug": prop["slug"], "phase": prop["phase"],
            "note": "Pending operator approval — it is not active until approved."}


@router.get("/learned-skills")
def learned_skills() -> dict:
    """List pending proposals and active (approved) learned skills."""
    from osprey.services.learned_skills import list_learned, list_proposals

    return {"proposals": list_proposals(), "active": list_learned()}


@router.post("/learned-skills/{proposal_id}/approve")
def approve_learned_skill(proposal_id: str) -> dict:
    """Operator gate: render an approved proposal into an active learned skill."""
    from osprey.services.learned_skills import LearnedSkillError, approve_proposal

    try:
        return {"status": "approved", **approve_proposal(proposal_id)}
    except LearnedSkillError as exc:
        raise HTTPException(400, detail=str(exc)) from exc


@router.delete("/learned-skills/{proposal_id}")
def reject_learned_skill(proposal_id: str) -> dict:
    """Operator gate: discard a pending proposal."""
    from osprey.services.learned_skills import reject_proposal

    if not reject_proposal(proposal_id):
        raise HTTPException(404, detail=f"No proposal with id: {proposal_id}")
    return {"status": "rejected", "id": proposal_id}


@router.post("/build-command")
def build_command_preview(proposal: ToolCallProposal) -> dict[str, str]:
    """
    Preview the CLI command the platform would run.

    Useful for your friend's agent loop: validate → build → execute via /mcp/execute.
    """
    validation = validate_tool_call(proposal)
    if not validation.approved:
        raise HTTPException(400, detail=validation.reason)

    cap = get_tool_capability(proposal.tool_name)
    freeform = cap.freeform_args_field if cap else "additional_args"
    command = build_command_for_tool(
        proposal.tool_name,
        validation.normalized_params,
        additional_args=proposal.additional_args,
        freeform_field=freeform,
    )
    return {"command": command, "tool_name": proposal.tool_name}
