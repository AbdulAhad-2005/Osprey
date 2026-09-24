"""World model + attack paths + questions + hypotheses —
plans/harness/05-world-model-and-attack-paths.md."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from osprey.schemas.attack_path import AttackPath, AttackPathListResponse, AttackPathStatus, AttackPathStep
from osprey.schemas.engagement_graph import AssetType
from osprey.schemas.reasoning import (
    Hypothesis,
    HypothesisListResponse,
    HypothesisStatus,
    Question,
    QuestionListResponse,
)
from osprey.services import attack_path_store, hypothesis_store, question_store, world_model

router = APIRouter()


class ProposeAttackPathRequest(BaseModel):
    engagement_id: str
    title: str
    steps: list[AttackPathStep] = Field(default_factory=list)


class AdvanceAttackPathRequest(BaseModel):
    status: AttackPathStatus | None = None
    finding_id: str = ""
    step: AttackPathStep | None = None


# --------------------------------------------------------------------------
# World model (Step 2)
# --------------------------------------------------------------------------

@router.get("/assets")
def list_assets(
    engagement_id: str = Query(...), asset_type: str | None = Query(default=None)
) -> dict[str, Any]:
    atype: AssetType | None = None
    if asset_type:
        try:
            atype = AssetType(asset_type.strip().lower())
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Unknown asset_type: {asset_type!r}")
    nodes = world_model.assets(engagement_id, atype)
    return {"assets": [n.model_dump(mode="json") for n in nodes], "total": len(nodes)}


@router.get("/related")
def list_related(
    engagement_id: str = Query(...), asset_id: str = Query(...), max_hops: int = Query(default=2),
) -> dict[str, Any]:
    result = world_model.related(engagement_id, asset_id, max_hops=max_hops)
    return {"related": result, "total": len(result)}


@router.get("/incomplete")
def list_incomplete(engagement_id: str = Query(...)) -> dict[str, Any]:
    result = world_model.assets_with_incomplete_investigation(engagement_id)
    return {"assets": result, "total": len(result)}


@router.get("/unexplained")
def list_unexplained(engagement_id: str = Query(...)) -> dict[str, Any]:
    result = world_model.unexplained_observations(engagement_id)
    return {"observations": result, "total": len(result)}


@router.get("/conflicts")
def list_conflicts(engagement_id: str = Query(...)) -> dict[str, Any]:
    result = world_model.conflicts(engagement_id)
    return {"conflicts": result, "total": len(result)}


# --------------------------------------------------------------------------
# Attack paths (Step 3)
# --------------------------------------------------------------------------

@router.post("/attack-paths", response_model=AttackPath)
def propose_attack_path(request: ProposeAttackPathRequest) -> AttackPath:
    try:
        return attack_path_store.propose(request.engagement_id, title=request.title, steps=request.steps)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/attack-paths", response_model=AttackPathListResponse)
def list_attack_paths(engagement_id: str = Query(...), active_only: bool = Query(default=True)) -> AttackPathListResponse:
    paths = attack_path_store.list_active(engagement_id) if active_only else attack_path_store.list_for_engagement(engagement_id)
    return AttackPathListResponse(attack_paths=paths, total=len(paths))


@router.get("/attack-paths/{path_id}", response_model=AttackPath)
def get_attack_path(path_id: str) -> AttackPath:
    path = attack_path_store.get(path_id)
    if path is None:
        raise HTTPException(status_code=404, detail=f"no attack path with id '{path_id}'")
    return path


@router.post("/attack-paths/{path_id}/advance", response_model=AttackPath)
def advance_attack_path(path_id: str, request: AdvanceAttackPathRequest) -> AttackPath:
    updated = attack_path_store.advance(
        path_id, status=request.status, append_step=request.step, finding_id=request.finding_id,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail=f"no attack path with id '{path_id}'")
    return updated


# --------------------------------------------------------------------------
# Questions (Step 4)
# --------------------------------------------------------------------------

@router.post("/questions", response_model=Question)
def raise_question(
    engagement_id: str = Query(...), text: str = Query(...),
    raised_by: str = Query(default="llm"), related_asset_id: str = Query(default=""),
) -> Question:
    try:
        return question_store.raise_question(
            engagement_id, text=text, raised_by=raised_by, related_asset_id=related_asset_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/questions", response_model=QuestionListResponse)
def list_questions(engagement_id: str = Query(...), open_only: bool = Query(default=True)) -> QuestionListResponse:
    items = question_store.list_open(engagement_id) if open_only else question_store.list_for_engagement(engagement_id)
    return QuestionListResponse(questions=items, total=len(items))


@router.post("/questions/{question_id}/answer", response_model=Question)
def answer_question(question_id: str, answer_text: str = Query(...)) -> Question:
    q = question_store.answer(question_id, answer_text=answer_text)
    if q is None:
        raise HTTPException(status_code=404, detail=f"no question with id '{question_id}'")
    return q


@router.post("/questions/{question_id}/dismiss", response_model=Question)
def dismiss_question(question_id: str) -> Question:
    q = question_store.dismiss(question_id)
    if q is None:
        raise HTTPException(status_code=404, detail=f"no question with id '{question_id}'")
    return q


# --------------------------------------------------------------------------
# Hypotheses (Step 4)
# --------------------------------------------------------------------------

@router.post("/hypotheses", response_model=Hypothesis)
def raise_hypothesis(
    engagement_id: str = Query(...), statement: str = Query(...),
    supporting_observation_ids: list[str] = Query(default=[]),
) -> Hypothesis:
    try:
        return hypothesis_store.raise_hypothesis(
            engagement_id, statement=statement, supporting_observation_ids=supporting_observation_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/hypotheses", response_model=HypothesisListResponse)
def list_hypotheses(engagement_id: str = Query(...), active_only: bool = Query(default=True)) -> HypothesisListResponse:
    items = hypothesis_store.list_active(engagement_id) if active_only else hypothesis_store.list_for_engagement(engagement_id)
    return HypothesisListResponse(hypotheses=items, total=len(items))


@router.post("/hypotheses/{hypothesis_id}/evidence", response_model=Hypothesis)
def add_hypothesis_evidence(
    hypothesis_id: str, observation_id: str = Query(...), supports: bool = Query(...),
) -> Hypothesis:
    h = hypothesis_store.add_evidence(hypothesis_id, observation_id=observation_id, supports=supports)
    if h is None:
        raise HTTPException(status_code=404, detail=f"no hypothesis with id '{hypothesis_id}'")
    return h


@router.post("/hypotheses/{hypothesis_id}/resolve", response_model=Hypothesis)
def resolve_hypothesis(hypothesis_id: str, status: str = Query(...)) -> Hypothesis:
    try:
        parsed = HypothesisStatus(status.strip().lower())
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Unknown status: {status!r}")
    try:
        h = hypothesis_store.resolve(hypothesis_id, status=parsed)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if h is None:
        raise HTTPException(status_code=404, detail=f"no hypothesis with id '{hypothesis_id}'")
    return h
