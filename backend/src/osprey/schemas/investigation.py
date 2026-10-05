"""Typed contract between an external harness and backend investigation capabilities."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from osprey.schemas.jobs import JobSummary


class CapabilityKind(StrEnum):
    """A category label for grouping/priority display only — never a unit of
    execution. Exactly one opportunity always maps to exactly one real
    action: either one typed-tool invocation (``opportunity.tool`` is set)
    or one pure-store analytical operation (DETECT_ANOMALIES/
    REFRESH_EXPLOIT_CANDIDATES, which touch no Kali tool at
    all). A capability that used to fan out several different tools inside
    one execution (the old ENUMERATE_SUBDOMAINS/PROFILE_HOST_SERVICES) is
    gone — each of those tools is now its own opportunity with its own kind,
    so nothing is ever hidden behind a batched call."""

    DISCOVER_RELATED_DOMAINS = "discover_related_domains"
    HARVEST_CONTACTS = "harvest_contacts"
    ENUMERATE_SUBDOMAINS = "enumerate_subdomains"
    RESOLVE_ASSETS = "resolve_assets"
    PROBE_LIVE_ASSETS = "probe_live_assets"
    PROBE_WEB_DEPTH = "probe_web_depth"
    ATTRIBUTE_ORIGIN = "attribute_origin"
    QUERY_PASSIVE_INTEL = "query_passive_intel"
    VERSION_SERVICES = "version_services"
    RETRY_CONNECT_SCAN = "retry_connect_scan"
    SCAN_NETWORK_VULNERABILITIES = "scan_network_vulnerabilities"
    SWEEP_NETBLOCK = "sweep_netblock"
    ASSESS_VULNERABILITY = "assess_vulnerability"
    DETECT_ANOMALIES = "detect_anomalies"
    REFRESH_EXPLOIT_CANDIDATES = "refresh_exploit_candidates"


class StepStatus(StrEnum):
    READY = "ready"
    WAITING = "waiting"
    COMPLETE = "complete"
    BLOCKED = "blocked"


class OpportunitySubject(BaseModel):
    asset_id: str
    asset_type: str
    label: str
    evidence_ids: list[str] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)


class InvestigationOpportunity(BaseModel):
    id: str
    capability: CapabilityKind
    reason: str
    priority: int = 0
    priority_factors: dict[str, float] = Field(default_factory=dict)
    cost: str = "low"
    risk: str = "passive"
    subjects: list[OpportunitySubject] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    # The exact single tool invocation this opportunity represents. Empty for
    # the analytical kinds (DETECT_ANOMALIES/REFRESH_EXPLOIT_CANDIDATES),
    # which touch no Kali tool. When set,
    # executing this opportunity means calling this tool with these params
    # exactly once — never a batch, never several tools behind one id.
    tool: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    additional_args: str = ""
    # 0 = unset, caller falls back to a generic default. A real value is a
    # deliberate ceiling for this class of tool (e.g. a passive apex-level
    # OSINT lookup gets a short one; a full port sweep gets a long one) — see
    # investigation_capabilities.py's per-stage timeout constants. Restores
    # the tuned-per-stage ceiling the pre-atomic engine had; its absence let
    # a single hung call inherit the execution kernel's generic 900s budget,
    # tripled by the kernel's own retry-on-timeout behavior.
    timeout: int = 0


class InvestigationStep(BaseModel):
    engagement_id: str
    run_id: str = ""
    revision: str
    status: StepStatus
    state_summary: str
    opportunities: list[InvestigationOpportunity] = Field(default_factory=list)
    active_jobs: list[JobSummary] = Field(default_factory=list)


class InvestigationStepRequest(BaseModel):
    engagement_id: str = Field(..., min_length=1)
    run_id: str = ""
    opportunity_id: str = Field(..., min_length=1)
    expected_revision: str = Field(..., min_length=1)
    driver: str = Field(default="external_harness", max_length=128)
    rationale: str = Field(default="", max_length=2000)


class InvestigationDecision(BaseModel):
    accepted: bool
    decision: str
    revision: str
    opportunity: InvestigationOpportunity | None = None
    job: JobSummary | None = None


class CapabilityResult(BaseModel):
    engagement_id: str
    run_id: str = ""
    opportunity_id: str
    capability: CapabilityKind
    success: bool
    changed: int = 0
    exhausted: bool = False
    stopped_reason: str = "completed"
    evidence_ids: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
