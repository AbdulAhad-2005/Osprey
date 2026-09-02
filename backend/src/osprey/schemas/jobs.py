"""Background / parallel job models — fire long tools, keep working, collect later."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class JobKind(StrEnum):
    TOOL = "tool"
    SHELL = "shell"
    SCRIPT = "script"
    EXPANSION = "expansion"
    # A scoped LLM sub-agent loop (recon/vuln/exploit/…) bound to the same
    # engagement blackboard — the unit of the multi-agent phase pipeline. Spawned
    # by the phase supervisor, by another agent (spawn_agent), or via MCP.
    AGENT = "agent"
    # Deterministic, no-LLM, no-sister-domain-expansion pipeline: whois ->
    # direct subdomain enumeration -> resolve to IPs -> nmap deep scan
    # (service + OS + tuned min-rate) per unique IP. See services/fast_scan.py.
    FAST_SCAN = "fast_scan"


# Roles a spawned agent can take. Each maps to a phase tool-catalog inside
# PhaseAgent; "custom" runs with recon tools + a free-form task.
AGENT_ROLES = ("recon", "network", "vuln", "web", "exploit", "osint", "custom")


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobStartRequest(BaseModel):
    kind: JobKind = JobKind.TOOL
    engagement_id: str = Field(..., min_length=1)
    run_id: str = ""
    label: str = Field(default="", description="Short human label for this branch")
    # catalog tool
    tool_name: str = ""
    params: dict[str, str | int | bool | None] = Field(default_factory=dict)
    additional_args: str = ""
    force_refresh: bool = False
    # shell
    command: str = ""
    # script
    code: str = ""
    language: str = "python3"
    packages: str = ""
    filename: str = ""
    reason: str = ""
    timeout: int = Field(default=300, ge=30, le=3600)
    record_findings: bool = True
    # kind=expansion
    max_passes: int = Field(default=5, ge=1, le=20)
    include_low_confidence: bool = Field(
        default=False,
        description=(
            "By default the engine holds back low-confidence origin-IP candidates "
            "(cdn_origin_probe confidence < 0.6) instead of port/vuln-scanning a guess "
            "that may belong to unrelated third-party infrastructure. Set true to scan "
            "them anyway."
        ),
    )
    # kind=agent — a scoped LLM sub-agent
    role: str = Field(default="recon", description="Agent role → phase tool catalog (see AGENT_ROLES)")
    task: str = Field(default="", description="Free-form goal for the sub-agent")
    scope: str = Field(default="", description="Optional asset/host/domain to focus on")
    max_turns: int = Field(default=0, ge=0, le=200, description="Agent turn cap (0 = server default)")
    depth: int = Field(default=0, ge=0, le=8, description="Spawn depth (fork-bomb guard)")
    parent_job_id: str = Field(default="", description="Job that spawned this one (lineage)")
    # kind=fast_scan
    target: str = Field(default="", description="Domain for the fast-scan pipeline")


class JobSummary(BaseModel):
    job_id: str
    engagement_id: str
    run_id: str = ""
    kind: JobKind
    status: JobStatus
    label: str = ""
    tool_name: str = ""
    command_preview: str = ""
    role: str = ""
    depth: int = 0
    parent_job_id: str = ""
    created_at: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None
    duration_seconds: float | None = None
    success: bool | None = None
    finding_titles: list[str] = Field(default_factory=list)
    error: str = ""
    hint: str = ""
    progress: str = Field(
        default="", description="Interim status while RUNNING — updated per step for multi-step kinds."
    )
    results_log: list[str] = Field(
        default_factory=list,
        description=(
            "Append-only structured results (stage/pass completions, findings summaries) — "
            "a caller should track how many entries it has already consumed and only render "
            "new ones, since `progress` alone can be overwritten between polls."
        ),
    )


class JobResultResponse(BaseModel):
    job: JobSummary
    result: dict[str, Any] | None = None
    note: str = (
        "On completed: findings already ingested if record_findings=true. "
        "Call platform_findings / platform_context / platform_thinking to analyze."
    )
