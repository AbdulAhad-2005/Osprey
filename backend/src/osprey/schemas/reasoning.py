"""Questions & hypotheses — the reasoning scaffold, plans/harness/05-world-
model-and-attack-paths.md Step 4. The bridge between "unexplained observation"
(world_model.unexplained_observations) and "attack path" (schemas.attack_path).
Cheap and written freely — no approval gate, unlike learned skills.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, Field


class QuestionStatus(StrEnum):
    OPEN = "open"
    ANSWERED = "answered"
    DISMISSED = "dismissed"


class Question(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str
    text: str
    status: QuestionStatus = QuestionStatus.OPEN
    raised_by: str = "llm"  # "llm" | "planner" (Plan 09's deterministic auto-raise)
    related_asset_id: str = ""
    answer: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HypothesisStatus(StrEnum):
    ACTIVE = "active"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


class Hypothesis(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str
    statement: str
    status: HypothesisStatus = HypothesisStatus.ACTIVE
    supporting_observation_ids: list[str] = Field(default_factory=list)
    contradicting_observation_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class QuestionListResponse(BaseModel):
    questions: list[Question]
    total: int


class HypothesisListResponse(BaseModel):
    hypotheses: list[Hypothesis]
    total: int
