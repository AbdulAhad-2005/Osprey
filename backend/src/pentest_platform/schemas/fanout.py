"""Explicit fan-out actions — never silent auto-chain."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FanoutSisterRequest(BaseModel):
    run_id: str | None = None
    tool_name: str = Field(
        default="subfinder_scan",
        description="Only subdomain-enum tools; default subfinder_scan. Never chains httpx/nmap.",
    )
    max_domains: int = Field(default=10, ge=1, le=50)
    timeout_per_tool: int = Field(default=180, ge=30, le=900)
    dry_run: bool = Field(
        default=True,
        description="If true (default), only preview domains — does not execute tools.",
    )
    confirm: bool = Field(
        default=False,
        description="Must be true together with dry_run=false to actually run tools.",
    )
    skip_already_marked: bool = Field(
        default=True,
        description="Skip domains that already have a soft tool_coverage mark for this tool.",
    )
    min_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Only include sister_unenumerated gaps at/above this confidence.",
    )


class FanoutDomainResult(BaseModel):
    domain: str
    gap_confidence: float = 0.0
    planned: bool = True
    executed: bool = False
    skipped: bool = False
    skip_reason: str = ""
    success: bool | None = None
    findings_count: int = 0
    finding_titles: list[str] = Field(default_factory=list)
    error: str = ""
    command: str = ""


class FanoutSisterResponse(BaseModel):
    engagement_id: str
    action: str = "enumerate_pending_sisters"
    dry_run: bool
    executed: bool
    tool_name: str
    domains_considered: int = 0
    domains_planned: int = 0
    domains_executed: int = 0
    domains_skipped: int = 0
    total_findings: int = 0
    results: list[FanoutDomainResult] = Field(default_factory=list)
    note: str = (
        "Explicit helper only — does not auto-run after domain_hunter. "
        "Does not chain httpx/nmap. Prefer dry_run first."
    )
    extra: dict[str, Any] = Field(default_factory=dict)
