"""Background job store + runner — parallel branches for long tools."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Callable

from osprey.schemas.jobs import (
    JobKind,
    JobResultResponse,
    JobStartRequest,
    JobStatus,
    JobSummary,
)
from osprey.schemas.tools import ToolExecutionRequest, ToolExecutionResponse

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
    )

    def __init__(self, req: JobStartRequest) -> None:
        self.job_id = f"job_{uuid.uuid4().hex[:12]}"
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
        elif req.kind == JobKind.EXPANSION:
            self.tool_name = self.tool_name or "surface_expand"
        elif req.kind == JobKind.AGENT:
            self.tool_name = self.tool_name or f"agent:{req.role}"
        elif req.kind == JobKind.FAST_SCAN:
            self.tool_name = self.tool_name or "fast_scan"
        self.command_preview = _preview(req)
        self.request = req
        self.created_at = time.time()
        self.started_at: float | None = None
        self.finished_at: float | None = None
        # ToolExecutionResponse for TOOL/SHELL/SCRIPT; ExpansionReport for EXPANSION —
        # both are pydantic models with .model_dump(), which is all get_result() needs.
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


def _default_label(req: JobStartRequest) -> str:
    if req.kind == JobKind.TOOL:
        return f"{req.tool_name}"
    if req.kind == JobKind.SHELL:
        return (req.command or "shell")[:60]
    if req.kind == JobKind.EXPANSION:
        return f"expand(max_passes={req.max_passes})"
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
    if req.kind == JobKind.EXPANSION:
        return f"BFS surface expansion, up to {req.max_passes} passes"
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


class JobStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, _JobRecord] = {}

    def list_for_engagement(
        self,
        engagement_id: str,
        *,
        status: str = "",
        limit: int = 50,
    ) -> list[JobSummary]:
        with self._lock:
            rows = [j for j in self._jobs.values() if j.engagement_id == engagement_id]
        if status:
            rows = [j for j in rows if j.status.value == status]
        rows.sort(key=lambda j: j.created_at, reverse=True)
        return [self._to_summary(j) for j in rows[: max(1, min(limit, 100))]]

    def get(self, job_id: str) -> JobSummary | None:
        with self._lock:
            j = self._jobs.get(job_id)
            if j is not None:
                return self._to_summary(j)
        return _durable_summary(job_id)

    def get_result(self, job_id: str) -> JobResultResponse | None:
        with self._lock:
            j = self._jobs.get(job_id)
            if j is not None:
                summary = self._to_summary(j)
                result = _serialize_result(j.result)
                return JobResultResponse(job=summary, result=result)
        # Not in memory — either pruned (_MAX_JOBS_KEPT) or the backend restarted
        # since this job ran. The task itself cannot be resumed either way, but
        # the durable row (persisted at start + at every terminal state — see
        # _persist_job) still has the real status/result, so platform_job_poll/
        # platform_job_result don't come back "unknown job" for work that
        # genuinely happened.
        from osprey.services.scan_run_store import get_scan_run_store

        row = get_scan_run_store().get(job_id)
        if row is None:
            return None
        return JobResultResponse(job=_durable_summary_from_row(row), result=row.get("result"))

    def cancel(self, job_id: str) -> JobSummary | None:
        """Stop a running job early. Findings are ingested incrementally as each
        tool completes, so everything discovered before the stop is already
        durable — cancelling just halts further work. Returns the (now
        CANCELLED) summary, or None if the job is unknown.
        """
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return None
            if record.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
                return self._to_summary(record)
            task = record.task
            record.status = JobStatus.CANCELLED
            record.finished_at = time.time()
            if not record.error:
                record.error = "stopped by user — findings gathered so far are saved"
            summary = self._to_summary(record)
        # Cancel the asyncio task outside the lock; its CancelledError unwinds the
        # run at the next await boundary (mid-tool subprocesses are best-effort).
        if task is not None and not task.done():
            task.cancel()
        # Persist the partial run now — the task's own terminal-persist path is
        # skipped because CancelledError bypasses its except-Exception handler.
        with self._lock:
            rec = self._jobs.get(job_id)
        if rec is not None:
            self._persist_job(rec)
        return summary

    def running_count(self, engagement_id: str, *, kind: JobKind | None = None) -> int:
        with self._lock:
            return sum(
                1
                for j in self._jobs.values()
                if j.engagement_id == engagement_id
                and j.status in (JobStatus.QUEUED, JobStatus.RUNNING)
                and (kind is None or j.kind == kind)
            )

    def total_count(self, engagement_id: str, *, kind: JobKind | None = None) -> int:
        """Every job ever created for the engagement (for spawn-budget guards)."""
        with self._lock:
            return sum(
                1
                for j in self._jobs.values()
                if j.engagement_id == engagement_id and (kind is None or j.kind == kind)
            )

    def list_active_agents(self, engagement_id: str) -> list[JobSummary]:
        with self._lock:
            rows = [
                j
                for j in self._jobs.values()
                if j.engagement_id == engagement_id
                and j.kind == JobKind.AGENT
                and j.status in (JobStatus.QUEUED, JobStatus.RUNNING)
            ]
        return [self._to_summary(j) for j in rows]

    def create_and_spawn(self, req: JobStartRequest) -> JobSummary:
        if not (req.engagement_id or "").strip():
            raise ValueError("engagement_id required")
        if req.kind == JobKind.TOOL and not (req.tool_name or "").strip():
            raise ValueError("tool_name required for kind=tool")
        if req.kind == JobKind.SHELL and not (req.command or "").strip():
            raise ValueError("command required for kind=shell")
        if req.kind == JobKind.SCRIPT and not (req.code or "").strip():
            raise ValueError("code required for kind=script")
        if req.kind == JobKind.FAST_SCAN and not (req.target or "").strip():
            raise ValueError("target required for kind=fast_scan")

        from osprey.services.parallelism_config import (
            agent_spawn_budget,
            max_running_agents,
            max_running_jobs,
            max_spawn_depth,
        )

        if req.kind == JobKind.AGENT:
            from osprey.services.llm_service import llm_configured, llm_not_configured_message

            if not llm_configured():
                # The direct platform_spawn_agent path (its REST endpoint turns
                # this ValueError into a clear HTTP 429 detail message) — a
                # PhaseAgent job would otherwise queue, run, and only fail
                # once it makes its first real completion() call. Note:
                # phase_supervisor.start_pipeline() (platform_pipeline's MCP
                # path) deliberately does NOT call llm_configured() at all
                # anymore — it never auto-spawns regardless of key state, so
                # this gate only applies to the explicit platform_spawn_agent
                # opt-in, not the conductor's read-only readiness call.
                raise ValueError(llm_not_configured_message())
            # Agents draw on a SEPARATE slot pool from tool jobs, plus a lifetime
            # budget and a nesting-depth cap so an agent that spawns agents can't
            # fork-bomb the engagement.
            if req.depth > max_spawn_depth():
                raise ValueError(
                    f"Spawn depth {req.depth} exceeds cap {max_spawn_depth()} — "
                    "an agent chain nested too deep; do this work in the current agent."
                )
            budget = agent_spawn_budget()
            if self.total_count(req.engagement_id, kind=JobKind.AGENT) >= budget:
                raise ValueError(
                    f"Agent spawn budget exhausted ({budget}) for this engagement."
                )
            cap = max_running_agents()
            running = self.running_count(req.engagement_id, kind=JobKind.AGENT)
            if running >= cap:
                raise ValueError(
                    f"Too many concurrent agents ({running}/{cap}). "
                    "Let one finish (platform_job_poll) before spawning more."
                )
        else:
            cap = max_running_jobs()
            running = self.running_count(req.engagement_id) - self.running_count(
                req.engagement_id, kind=JobKind.AGENT
            )
            if running >= cap:
                raise ValueError(
                    f"Too many parallel jobs ({running}/{cap}). "
                    "Poll completed jobs before starting more."
                )

        record = _JobRecord(req)
        with self._lock:
            self._jobs[record.job_id] = record
            self._prune_locked()

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError as exc:
            raise ValueError("Background jobs require an async server event loop") from exc

        record.task = loop.create_task(self._run(record.job_id), name=record.job_id)
        logger.info(
            "job spawned id=%s engagement=%s kind=%s label=%s",
            record.job_id,
            record.engagement_id,
            record.kind,
            record.label,
        )
        # Durable job history — every kind, not just EXPANSION (best-effort; never blocks).
        self._persist_job(record)
        return self._to_summary(record)

    def _persist_job(self, record: _JobRecord) -> None:
        """Mirror a job's lifecycle into the durable scan_runs table (any kind —
        tool/shell/script/expansion/agent) so job state survives a restart or a
        job-store prune (_MAX_JOBS_KEPT). Previously this only ran for
        kind=expansion, so every AGENT job platform_pipeline/platform_spawn_agent
        create — and every TOOL/SHELL/SCRIPT job — vanished on restart with no
        trace; get()/get_result() fall back to this table (see _durable_summary)
        when the in-memory record is gone. Best-effort; never blocks the job."""
        try:
            from osprey.services.engagement_store import get_engagement_store
            from osprey.services.scan_run_store import get_scan_run_store

            eng = get_engagement_store().get(record.engagement_id)
            result = record.result.model_dump() if record.result is not None else None
            get_scan_run_store().upsert(
                job_id=record.job_id,
                engagement_id=record.engagement_id,
                run_id=record.run_id,
                kind=record.kind.value,
                label=record.label,
                target=getattr(eng, "target", "") or "",
                status=record.status.value,
                max_passes=record.request.max_passes,
                include_low_confidence=record.request.include_low_confidence,
                progress=record.progress,
                results_log=list(record.results_log),
                result=result,
                error=record.error,
                started_at=record.started_at,
                finished_at=record.finished_at,
            )
        except Exception:  # noqa: BLE001
            logger.debug("scan-run persist failed id=%s (non-fatal)", record.job_id, exc_info=True)

    def _prune_locked(self) -> None:
        if len(self._jobs) <= _MAX_JOBS_KEPT:
            return
        # Never prune a job that finished within the grace window — a job that
        # completes while the chat is busy must still be fetchable by the time
        # the operator gets to it (the durable row survives regardless, but this
        # keeps the full in-memory record — results_log + result — around too).
        now = time.time()
        finished = sorted(
            (
                j
                for j in self._jobs.values()
                if j.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)
                and (now - (j.finished_at or j.created_at)) > _PRUNE_GRACE_SECONDS
            ),
            key=lambda j: j.finished_at or j.created_at,
        )
        while len(self._jobs) > _MAX_JOBS_KEPT and finished:
            old = finished.pop(0)
            self._jobs.pop(old.job_id, None)

    async def _run(self, job_id: str) -> None:
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return
            record.status = JobStatus.RUNNING
            record.started_at = time.time()
            req = record.request
        # Persist the RUNNING transition so the durable row isn't stuck at
        # QUEUED — a restart mid-run then leaves a reconcilable 'running'
        self._persist_job(record)

        def _on_progress(text: str) -> None:
            with self._lock:
                rec = self._jobs.get(job_id)
                if rec is None:
                    return
                if text.startswith("RESULT::"):
                    rec.results_log.append(text[len("RESULT::"):][:500])
                    if len(rec.results_log) > 500:
                        rec.results_log = rec.results_log[-500:]
                else:
                    rec.progress = text[:500]

        try:
            response = await self._execute(req, on_progress=_on_progress, job_id=job_id)
            with self._lock:
                record = self._jobs.get(job_id)
                if record is None:
                    return
                record.result = response
                if isinstance(response, ToolExecutionResponse):
                    record.status = JobStatus.COMPLETED if response.success else JobStatus.FAILED
                    if not response.success:
                        record.error = (response.error or response.stderr or "tool failed")[:2000]
                elif req.kind == JobKind.AGENT:
                    # AgentResponse carries its own .success (e.g. max_turns_exceeded,
                    # an unhandled agent error) — reaching this line at all does NOT
                    # mean the agent's task succeeded, unlike EXPANSION below where
                    # per-step failures are already absorbed internally.
                    agent_ok = bool(getattr(response, "success", True))
                    record.status = JobStatus.COMPLETED if agent_ok else JobStatus.FAILED
                    if not agent_ok:
                        record.error = str(
                            getattr(response, "error", "")
                            or getattr(response, "final_message", "")
                            or "agent failed"
                        )[:2000]
                else:
                    # Multi-step kinds (EXPANSION): per-step failures are already
                    # handled internally and never abort the loop — reaching here
                    # at all means the loop completed, full stop.
                    record.status = JobStatus.COMPLETED
                record.finished_at = time.time()
        except Exception as exc:  # noqa: BLE001
            logger.exception("background job failed id=%s", job_id)
            with self._lock:
                record = self._jobs.get(job_id)
                if record is None:
                    return
                record.status = JobStatus.FAILED
                record.error = f"{type(exc).__name__}: {exc}"[:2000]
                record.finished_at = time.time()

        # Persist the terminal state (outside the lock — DB I/O shouldn't block
        # other job ops). Best-effort, any kind.
        with self._lock:
            record = self._jobs.get(job_id)
        if record is not None:
            self._persist_job(record)

    async def _execute(
        self, req: JobStartRequest, *, on_progress: Callable[[str], None] | None = None,
        job_id: str = "",
    ) -> ToolExecutionResponse | Any:
        if req.kind == JobKind.EXPANSION:
            from osprey.services.surface_expansion import (
                _MIN_ORIGIN_CONFIDENCE,
                run_expansion_to_fixpoint,
            )

            # Lead the run with the execution backend in use, so it's always
            # obvious from the results log whether tools ran in Kali (docker) or
            # natively — the difference between real output and silent failures.
            if on_progress is not None:
                try:
                    from osprey.services.mcp_client import get_mcp_client

                    st = get_mcp_client().execution_status()
                    on_progress(f"RESULT::⚙ execution: {st.get('message', 'unknown')}")
                except Exception:  # noqa: BLE001
                    logger.debug("could not report execution status", exc_info=True)

            def _pass_cb(pass_report: Any) -> None:
                if on_progress is None:
                    return
                d = pass_report.delta
                # RESULT:: — same persistent-vs-ephemeral convention as the
                # in-pass stage reports: a pass boundary is itself a result
                # worth keeping visible, not something the next line should
                # silently overwrite.
                on_progress(
                    f"RESULT::■ pass {pass_report.pass_number}/{req.max_passes} complete: "
                    f"{d.frontier_processed} seed(s) -> +{d.new_nodes} assets, +{d.new_edges} edges"
                    + (" — exhausted" if d.exhausted else "")
                )

            return await run_expansion_to_fixpoint(
                engagement_id=req.engagement_id, run_id=req.run_id or "",
                max_passes=req.max_passes, on_pass=_pass_cb, on_progress=on_progress,
                min_origin_confidence=0.0 if req.include_low_confidence else _MIN_ORIGIN_CONFIDENCE,
            )
        if req.kind == JobKind.AGENT:
            from osprey.services import event_bus
            from osprey.services.agent_runner import run_scoped_agent

            async def _agent_progress(event: str, data: dict[str, Any]) -> None:
                # The one place a spawned phase agent's own tool calls become
                # visible: published onto the engagement's shared event bus so
                # the Commander's persistent live stream shows them inline,
                # attributed by role/job_id — not just recorded into this
                # job's own progress text (kept below for `platform_job_poll`'s
                # existing pull-style MCP contract, unrelated to this fix).
                event_bus.publish(
                    req.engagement_id, event, {**data, "job_id": job_id}, source=f"agent:{req.role}"
                )
                if on_progress is None:
                    return
                # Ephemeral "what's happening right now" (overwritten each call) —
                # same convention EXPANSION jobs use for in-progress status.
                if event == "tool_start":
                    on_progress(f"{req.role}: running {data.get('tool_name', '?')}")
                    return
                if event == "status":
                    on_progress(str(data.get("message", "")))
                    return
                # Persistent turn-by-turn history — same RESULT:: convention
                # EXPANSION uses for pass boundaries, so platform_job_poll shows a
                # real activity log for backend-driven phase agents, not just the
                # latest "started" line overwriting the previous one. This is what
                # makes the auto-executor path genuinely watchable turn-by-turn
                # instead of fire-and-forget.
                if event == "tool_end":
                    tool_name = data.get("tool_name", "?")
                    ok = "ok" if data.get("success") else "FAIL"
                    preview = str(data.get("preview") or "")[:200].replace("\n", " ")
                    on_progress(f"RESULT::[{req.role}] {tool_name} ({ok}): {preview}")
                elif event == "assistant":
                    content = str(data.get("content") or "")[:300].replace("\n", " ")
                    if content:
                        on_progress(f"RESULT::[{req.role}] narrative: {content}")
                elif event == "phase_done":
                    ok = "success" if data.get("success") else "stopped"
                    calls = data.get("tool_calls", "?")
                    on_progress(f"RESULT::[{req.role}] phase done ({ok}, {calls} tool call(s))")
                elif event == "error":
                    on_progress(f"RESULT::[{req.role}] ERROR: {str(data.get('message') or '')[:200]}")

            return await run_scoped_agent(
                engagement_id=req.engagement_id,
                run_id=req.run_id or "",
                role=req.role,
                task=req.task,
                scope=req.scope,
                max_turns=req.max_turns,
                on_event=_agent_progress,
            )
        if req.kind == JobKind.FAST_SCAN:
            from osprey.services.fast_scan import run_fast_scan

            return await run_fast_scan(
                req.engagement_id, req.run_id or "", req.target,
                on_progress=on_progress,
            )
        if req.kind == JobKind.TOOL:
            from osprey.services.tool_execution import execute_tool_request

            return await execute_tool_request(
                ToolExecutionRequest(
                    tool_name=req.tool_name,
                    params=req.params,
                    engagement_id=req.engagement_id,
                    run_id=req.run_id or None,
                    timeout=req.timeout,
                    additional_args=req.additional_args,
                    force_refresh=req.force_refresh,
                    use_cache=not req.force_refresh,
                    record_findings=req.record_findings,
                    use_recovery=True,
                )
            )
        if req.kind == JobKind.SHELL:
            from osprey.services.shell_exec import execute_shell_request

            return await execute_shell_request(
                command=req.command,
                engagement_id=req.engagement_id,
                run_id=req.run_id or None,
                reason=req.reason or req.label,
                timeout=min(req.timeout, _JOB_MAX_TIMEOUT),
                record_findings=req.record_findings,
            )
        from osprey.services.script_exec import execute_script_request

        return await execute_script_request(
            code=req.code,
            language=req.language,
            engagement_id=req.engagement_id,
            run_id=req.run_id or None,
            reason=req.reason or req.label,
            timeout=min(req.timeout, _JOB_MAX_TIMEOUT),
            filename=req.filename,
            packages=req.packages,
            record_findings=req.record_findings,
        )

    def _to_summary(self, j: _JobRecord) -> JobSummary:
        dur = None
        if j.started_at and j.finished_at:
            dur = round(j.finished_at - j.started_at, 2)
        elif j.started_at and j.status == JobStatus.RUNNING:
            dur = round(time.time() - j.started_at, 2)

        titles: list[str] = []
        success = None
        if j.result is not None:
            if isinstance(j.result, ToolExecutionResponse):
                titles = list(j.result.finding_titles or [])[:40]
                success = bool(j.result.success)
            elif j.kind == JobKind.AGENT:
                # AgentResponse — findings already landed in the shared store; the
                # summary carries success + the agent's closing message (via
                # get_result's model_dump), not a title list.
                success = bool(getattr(j.result, "success", True))
            else:
                # ExpansionReport — flatten each pass's new_finding_titles.
                titles = [t for p in getattr(j.result, "passes", []) for t in p.new_finding_titles][:40]
                success = True

        hint = ""
        if j.status == JobStatus.RUNNING:
            if j.kind == JobKind.EXPANSION:
                hint = (
                    f"Still expanding — progress: {j.progress or 'starting…'}. "
                    "Poll again after doing other work, or use platform_job_poll(wait_seconds=20) "
                    "to block briefly instead of polling repeatedly."
                )
            else:
                hint = "Still running — continue other work; poll later with platform_job_poll."
        elif j.status == JobStatus.COMPLETED and j.kind == JobKind.EXPANSION:
            hint = "Done — call platform_job_result for the full pass-by-pass expansion report."
        elif j.status == JobStatus.COMPLETED and j.kind == JobKind.AGENT:
            hint = (
                "Sub-agent finished — its findings are in shared engagement memory. "
                "Call platform_findings / platform_context to build on them, or "
                "platform_job_result for the agent's closing report."
            )
        elif j.status == JobStatus.CANCELLED:
            hint = (
                "Stopped by user — findings gathered before the stop are saved; "
                "review with /findings, or re-spawn if this phase is worth resuming."
            )
        elif j.status == JobStatus.COMPLETED:
            hint = (
                "Done — findings ingested. Call platform_job_result for stdout, then "
                "platform_findings / platform_thinking to analyze this branch."
            )
        elif j.status == JobStatus.FAILED:
            hint = "Failed — read error; retry with smaller scope or platform_script."
        elif j.status == JobStatus.QUEUED:
            hint = "Queued — about to start."

        return JobSummary(
            job_id=j.job_id,
            engagement_id=j.engagement_id,
            run_id=j.run_id,
            kind=j.kind,
            status=j.status,
            label=j.label,
            tool_name=j.tool_name,
            command_preview=j.command_preview,
            role=(j.request.role if j.kind == JobKind.AGENT else ""),
            depth=j.request.depth,
            parent_job_id=j.request.parent_job_id,
            created_at=j.created_at,
            started_at=j.started_at,
            finished_at=j.finished_at,
            duration_seconds=dur,
            success=success,
            finding_titles=titles,
            error=j.error,
            hint=hint,
            progress=j.progress,
            results_log=list(j.results_log),
        )


_store: JobStore | None = None


def get_job_store() -> JobStore:
    global _store
    if _store is None:
        _store = JobStore()
    return _store


def suggest_background(tool_name: str, timeout: int) -> bool:
    """Heuristic: long tools / high timeouts should be branched (config-driven)."""
    from osprey.services.parallelism_config import suggest_background as _sug

    return _sug(tool_name, timeout)
