"""Attack path — a first-class reasoning object, plans/harness/05-world-
model-and-attack-paths.md Step 3.

An ordered chain of (observation | asset | hypothesis) steps, each with a
rationale for why it connects to the next — the relationships *between*
observations that don't map to any single coverage category, e.g.: public
API endpoint -> internal endpoint reference (observation) -> different authz
boundary (observation) -> object identifier (observation) -> cross-user
access (hypothesis -> validated finding).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, Field


class AttackPathStepKind(StrEnum):
    OBSERVATION = "observation"
    ASSET = "asset"
    HYPOTHESIS = "hypothesis"


class AttackPathStep(BaseModel):
    kind: AttackPathStepKind
    ref_id: str  # observation_id | asset node id | hypothesis id
    rationale: str = ""  # why this hop connects to the next one


class AttackPathStatus(StrEnum):
    HYPOTHESIZED = "hypothesized"
    INVESTIGATING = "investigating"
    VALIDATED = "validated"
    DEAD = "dead"


class AttackPath(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str
    title: str
    steps: list[AttackPathStep] = Field(default_factory=list)
    status: AttackPathStatus = AttackPathStatus.HYPOTHESIZED
    # Set once a controlled PoC (Plan 03's evidence-producing capabilities)
    # reproduces the chain and a finding is filed for it.
    finding_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackPathListResponse(BaseModel):
    attack_paths: list[AttackPath]
    total: int
