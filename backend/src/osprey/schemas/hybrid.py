"""Hybrid recon/network orchestration schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from osprey.schemas.attack_surface import AttackSurfaceTree
from osprey.schemas.engagement_graph import GraphSummary
from osprey.schemas.network_surface import NetworkSurfaceSummary


class EscalationSuggestion(BaseModel):
    technique: str = ""
    signal: str = ""
    action: str
    tool_name: str | None = None
    additional_args: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    source: str = "escalation_matrix"


class DispatchSuggestion(BaseModel):
    signal: str
    task_id: str
    default_tool: str
    alternatives: list[str] = Field(default_factory=list)
    skill_file: str = ""
    reason: str = ""
    priority: int = 0


class CommanderContext(BaseModel):
    """Structured Commander view — consumed by any driving LLM (OpenCode, Claude,
    or our own CLI/GUI executor). Contains everything needed to decide the next
    step: memory (graph + findings), the full tool catalog, phase skills, the
    conductor's evidence-based phase-readiness signal, and the Commander role
    spec (``role_guidance``). One conductor, read identically by any executor —
    see phase_supervisor.phase_readiness_snapshot for how ``phase_readiness`` is
    computed."""

    phase: str
    catalog: dict[str, Any]
    skills: str
    role_guidance: str = ""
    findings_summary: str
    graph_summary: GraphSummary | None = None
    escalation_playbook: str = ""
    dispatch_rules: list[DispatchSuggestion] = Field(default_factory=list)
    active_pivots: list[str] = Field(default_factory=list)
    attack_surface_tree: AttackSurfaceTree | None = None
    attack_surface_tree_text: str = ""
    network_surface: NetworkSurfaceSummary | None = None
    network_surface_text: str = ""
    # Evidence-based conductor state: recon (always active) -> vuln/exploit
    # unlocked once their thresholds are met, plus loop-back candidates.
    # Informative, never a gate — the driving LLM decides what to do with it.
    phase_readiness: dict[str, Any] = Field(default_factory=dict)
    phase_readiness_text: str = ""
    # Elite operator surfaces
    skills_index: str = ""
    crown_jewels: list[dict[str, Any]] = Field(default_factory=list)
    context_delta: dict[str, Any] = Field(default_factory=dict)
    background_jobs: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Active/recent parallel job branches (job_id, status, label).",
    )
    jobs_line: str = Field(
        default="",
        description="Compact jobs: n/max running [labels] for context header.",
    )
    pipeline_line: str = Field(
        default="",
        description=(
            "Compact phase-pipeline status (running/finished, active agents) for "
            "context header — visibility into platform_pipeline without a separate call."
        ),
    )
    stdout_index: dict[str, Any] = Field(
        default_factory=dict,
        description="Recent tool artifact paths + snippets (full body on Kali).",
    )
    note: str = (
        "You are the operator. Full tool catalog is always available — phase skills "
        "steer, they never block. phase_readiness shows what evidence has unlocked so "
        "far; it's data, not an order. Invent with platform_script / graph_link when thin."
    )


class EscalationQuery(BaseModel):
    tool_name: str
    technique: str = ""
    error: str = ""
    stderr: str = ""
    stdout: str = ""
    returncode: int | None = None
    timed_out: bool = False
    target: str = ""


class HybridExecutionMeta(BaseModel):
    escalation_suggestions: list[EscalationSuggestion] = Field(default_factory=list)
    dispatch_suggestions: list[DispatchSuggestion] = Field(default_factory=list)
    graph_pivots: list[str] = Field(default_factory=list)
