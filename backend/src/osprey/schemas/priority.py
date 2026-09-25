"""Multi-factor priority score — plans/harness/06-prioritization-engine.md.

A score over a world-model item (observation | asset | question | attack_path)
answering "what's worth doing next", never "is this real" (that stays
confidence_for's job, Plan 03's one law — priority and confidence are
deliberately different numbers over different questions).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PriorityFactors(BaseModel):
    """One term per plans/harness/06 Step 1 factor — kept as a breakdown, not
    just a total, so a caller can see WHY something ranked where it did."""

    objective_relevance: float = 0.0
    evidence_strength: float = 0.0
    novelty: float = 0.0
    potential_impact: float = 0.0
    relationship_centrality: float = 0.0
    unexplained_behavior: float = 0.0
    validation_potential: float = 0.0
    coverage_importance: float = 0.0
    cost: float = 0.0
    repetition: float = 0.0
    risk: float = 0.0


class PriorityScore(BaseModel):
    item_id: str
    item_kind: str  # observation | asset | question | attack_path
    type_key: str = ""  # observation_type / asset_type / "question" / attack_path status
    target: str = ""
    label: str = ""
    total: float
    factors: PriorityFactors = Field(default_factory=PriorityFactors)


class PriorityListResponse(BaseModel):
    items: list[PriorityScore]
    total: int
