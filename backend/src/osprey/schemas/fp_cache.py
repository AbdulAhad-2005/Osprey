"""False-positive cache — plans/harness/04-learning-fp-cache.md.

A human judgment ("this recurring pattern is noise"), captured once via
``mark_false_positive``, applied forever: every future ``promote_observations``
/ ``platform_file_finding`` call consults these patterns before promotion.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class FpPattern(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    # "*" (cross-engagement, the default — a noise pattern on nginx is noise
    # everywhere) or an fnmatch glob to scope the mark to one target.
    target_glob: str = "*"
    # Empty = matches any finding type.
    finding_type: str = ""
    title_contains: str = ""
    # Optional exact match against an Observation's signature
    # (schemas.observation.observation_signature) — tighter than title_contains
    # when the operator wants to suppress one specific structural fact.
    observation_signature: str = ""
    reason: str = ""
    marked_by: str = "operator"
    marked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FpPatternListResponse(BaseModel):
    patterns: list[FpPattern]
    total: int


class SuppressedPromotion(BaseModel):
    """Audit record: a promotion that WOULD have happened but was suppressed
    by a matching FP pattern — visible, never a silent drop (Plan 04 Step 4)."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str
    observation_id: str = ""
    pattern_id: str
    title: str = ""
    reason: str = ""
    suppressed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
