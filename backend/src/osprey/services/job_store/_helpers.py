"""Background job store + runner — parallel branches for long tools."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from datetime import datetime
from typing import Any

from osprey.schemas.jobs import (
    JobKind,
    JobStartRequest,
    JobStatus,
    JobSummary,
)
from osprey.schemas.tools import ToolExecutionResponse

logger = logging.getLogger(__name__)

_MAX_JOBS_KEPT = 200

# Hard ceiling on a background job's wall-clock (shell/script lanes). Configurable
# via JOB_MAX_TIMEOUT_SECONDS; the bound still exists so a runaway job can't hold a
# slot forever, and partial stdout is drained + ingested on the kill regardless.
_JOB_MAX_TIMEOUT = max(60, int(os.getenv("JOB_MAX_TIMEOUT_SECONDS", "1800") or 1800))

# Finished jobs younger than this are exempt from count-based pruning, so a job
# that completed while the chat was busy is still retrievable when the operator
# fetches it (issue: nmap job pruned before its banners were read).
_PRUNE_GRACE_SECONDS = max(300, int(os.getenv("JOB_PRUNE_GRACE_SECONDS", "1800") or 1800))


class _JobRecord:
    __slots__ = (
        "job_id",
        "engagement_id",
        "run_id",
        "kind",
        "status",
        "label",
        "tool_name",
        "command_preview",
        "request",
        "created_at",
        "started_at",
        "finished_at",
        "result",
        "error",
        "task",
        "progress",
        "results_log",
        "last_persisted_at",
    )

    def __init__(self, req: JobStartRequest, *, existing: dict[str, "_JobRecord"] | None = None) -> None:
        self.engagement_id = req.engagement_id
        self.run_id = req.run_id or ""
        self.kind = req.kind
        self.status = JobStatus.QUEUED
        self.label = (req.label or "").strip() or _default_label(req)
        self.tool_name = (req.tool_name or "").strip()
        if req.kind == JobKind.SHELL:
            self.tool_name = self.tool_name or "shell"
        elif req.kind == JobKind.SCRIPT:
            self.tool_name = self.tool_name or f"script:{req.language}"
        elif req.kind == JobKind.INVESTIGATION_STEP:
            # req.tool is the opportunity's real tool (Plan 18: every
            # opportunity is exactly one real tool call) — show that, not a
            # synthetic "investigation:<capability>" label that hides which
            # tool is actually running. Only the three analytical kinds
            # (no tool at all) fall back to the capability label.
            self.tool_name = self.tool_name or req.tool or f"investigation:{req.capability}"
        elif req.kind == JobKind.AGENT:
            self.tool_name = self.tool_name or f"agent:{req.role}"
        elif req.kind == JobKind.FAST_SCAN:
            self.tool_name = self.tool_name or "fast_scan"
        # Human-readable, tool-named id ("job_nmap_service_scan1") instead of an
        # opaque uuid blob — an operator staring at platform_job_poll output (or
        # the dashboard) should be able to tell what a job IS from its id alone.
        # Numbered against siblings already in the store so repeat calls to the
        # same tool don't collide (job_nmap_service_scan1, ...2, ...3).
        self.job_id = _next_job_id(self.tool_name, existing or {})
        self.command_preview = _preview(req)
        self.request = req
        self.created_at = time.time()
        self.started_at: float | None = None
        self.finished_at: float | None = None
        # Capability and tool responses are pydantic models with .model_dump(),
        # which is all get_result() needs.
        self.result: ToolExecutionResponse | Any | None = None
        self.error = ""
        self.task: asyncio.Task[None] | None = None
        self.progress = ""
        # Structured, persistent results (RESULT:: lines) — append-only, unlike
        # `progress` which is a single "current status" slot a caller polling
        # every few seconds can easily miss overwrites of. A caller tracks how
        # many entries it has already seen and only prints the new ones, so a
        # stage-complete result can never be silently clobbered by the next
        # in-flight ticker update before the next poll happens to land.
        self.results_log: list[str] = []
        self.last_persisted_at = 0.0


def _serialize_result(result: Any) -> dict[str, Any] | None:
    """Serialize any job result to a dict — pydantic models (.model_dump) OR the
    AgentResponse dataclass (asdict) for kind=agent."""
    if result is None:
        return None
    if hasattr(result, "model_dump"):
        return result.model_dump()
    import dataclasses

    if dataclasses.is_dataclass(result):
        return dataclasses.asdict(result)
    return None


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify_tool(tool_name: str) -> str:
    slug = _SLUG_RE.sub("_", (tool_name or "job").strip().lower()).strip("_")
    return slug or "job"


def _next_job_id(tool_name: str, existing: dict[str, "_JobRecord"]) -> str:
    """job_<tool><n> — numbered against whatever's already in the store so
    repeat calls to the same tool get job_nmap_service_scan1, ...2, ...3
    instead of colliding or falling back to a uuid."""
    slug = _slugify_tool(tool_name)
    prefix = f"job_{slug}"
    taken = {rec.job_id for rec in existing.values()}
    n = 1
    while f"{prefix}{n}" in taken:
        n += 1
    return f"{prefix}{n}"


def _default_label(req: JobStartRequest) -> str:
    if req.kind == JobKind.TOOL:
        return f"{req.tool_name}"
    if req.kind == JobKind.SHELL:
        return (req.command or "shell")[:60]
    if req.kind == JobKind.INVESTIGATION_STEP:
        return f"investigation:{req.capability}"
    if req.kind == JobKind.AGENT:
        scope = f" [{req.scope}]" if req.scope else ""
        return f"agent:{req.role}{scope}"
    if req.kind == JobKind.FAST_SCAN:
        return f"fast-scan({req.target})"
    return f"script:{req.language}"


def _preview(req: JobStartRequest) -> str:
    if req.kind == JobKind.TOOL:
        return f"{req.tool_name}({req.params})"[:200]
    if req.kind == JobKind.SHELL:
        return (req.command or "")[:200]
    if req.kind == JobKind.INVESTIGATION_STEP:
        return f"{req.capability} on {len(req.subject_ids)} graph subject(s)"
    if req.kind == JobKind.AGENT:
        return f"{req.role} sub-agent: {(req.task or req.scope or 'run phase').strip()}"[:200]
    if req.kind == JobKind.FAST_SCAN:
        return (
            f"whois + subs + TLS SANs + resolve + CDN-classify + httpx + nmap "
            f"+ takeover check: {req.target}"
        )[:200]
    return f"{req.language} script {len(req.code or '')} bytes"


def _epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso).timestamp()
    except ValueError:
        return None


def _durable_summary_from_row(row: dict[str, Any]) -> JobSummary:
    """Reconstruct a read-only JobSummary from a durable scan_runs row — used
    when the in-memory record is gone (pruned, or the backend restarted)."""
    started = _epoch(row.get("started_at"))
    finished = _epoch(row.get("finished_at"))
    duration = round(finished - started, 2) if started is not None and finished is not None else None
    try:
        kind = JobKind(row.get("kind") or "tool")
    except ValueError:
        kind = JobKind.TOOL
    try:
        status = JobStatus(row.get("status") or "completed")
    except ValueError:
        status = JobStatus.COMPLETED

    result = row.get("result")
    request = row.get("request") if isinstance(row.get("request"), dict) else {}
    titles: list[str] = []
    success: bool | None = None
    if isinstance(result, dict):
        if "passes" in result:
            titles = [
                t for p in (result.get("passes") or []) for t in (p.get("new_finding_titles") or [])
            ][:40]
            success = True
        else:
            titles = list(result.get("finding_titles") or [])[:40]
            success = result.get("success")

    return JobSummary(
        job_id=str(row.get("job_id") or ""),
        engagement_id=str(row.get("engagement_id") or ""),
        run_id=str(row.get("run_id") or ""),
        kind=kind,
        status=status,
        label=str(row.get("label") or ""),
        tool_name=str(request.get("tool_name") or ""),
        command_preview=str(row.get("command_preview") or ""),
        role=str(request.get("role") or ""),
        depth=int(request.get("depth") or 0),
        parent_job_id=str(request.get("parent_job_id") or ""),
        opportunity_id=str(request.get("opportunity_id") or ""),
        capability=str(request.get("capability") or ""),
        driver=str(request.get("driver") or ""),
        created_at=_epoch(row.get("created_at")) or 0.0,
        started_at=started,
        finished_at=finished,
        duration_seconds=duration,
        success=success,
        finding_titles=titles,
        error=str(row.get("error") or ""),
        hint=(
            "Restored from durable storage — the live job record was gone (pruned or the "
            "backend restarted since this ran), but its final status/result survived."
        ),
        progress=str(row.get("progress") or ""),
        results_log=list(row.get("results_log") or []),
    )


def _durable_summary(job_id: str) -> JobSummary | None:
    from osprey.services.scan_run_store import get_scan_run_store

    row = get_scan_run_store().get(job_id)
    if row is None:
        return None
    return _durable_summary_from_row(row)


