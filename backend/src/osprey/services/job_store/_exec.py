"""JobStore job creation / run / execute / summary methods (mixin)."""

from __future__ import annotations
import asyncio
import time
from typing import Any, Callable
from osprey.schemas.jobs import (
    JobKind,
    JobStartRequest,
    JobStatus,
    JobSummary,
)
from osprey.schemas.tools import ToolExecutionRequest, ToolExecutionResponse
from osprey.services.job_store._helpers import (
    logger,
    _MAX_JOBS_KEPT,
    _JOB_MAX_TIMEOUT,
    _PRUNE_GRACE_SECONDS,
    _JobRecord,
    _serialize_result,
)


class _ExecMixin:

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
        if req.kind == JobKind.INVESTIGATION_STEP:
            from osprey.services.investigation_capabilities import (
                diagnose_revision_mismatch,
                list_step,
            )

            current = list_step(req.engagement_id, req.run_id)
            if current.revision != req.expected_revision:
                diff = diagnose_revision_mismatch(req.engagement_id, req.expected_revision, current.revision)
                logger.warning(
                    "stale investigation revision (job_store internal re-check) engagement=%s opportunity=%s: %s",
                    req.engagement_id, req.opportunity_id, diff,
                )
                raise ValueError(f"stale investigation revision: {diff}")
            opportunity = next(
                (item for item in current.opportunities if item.id == req.opportunity_id),
                None,
            )
            if opportunity is None:
                diff = diagnose_revision_mismatch(req.engagement_id, req.expected_revision, current.revision)
                logger.warning(
                    "investigation opportunity not current engagement=%s opportunity=%s revision=%s: %s",
                    req.engagement_id, req.opportunity_id, current.revision, diff,
                )
                raise ValueError(
                    f"investigation opportunity is not current (revision unchanged: {diff})"
                )
            expected_subjects = [subject.asset_id for subject in opportunity.subjects]
            if (
                req.capability != opportunity.capability.value
                or req.subject_ids != expected_subjects
                or req.capability_input != opportunity.evidence
                or req.tool != opportunity.tool
                or req.params != opportunity.params
                or req.additional_args != opportunity.additional_args
            ):
                raise ValueError("investigation capability payload does not match opportunity")

        from osprey.services.parallelism_config import (
            agent_spawn_budget,
            max_running_agents,
            max_running_jobs,
            max_spawn_depth,
        )

        if req.kind == JobKind.AGENT:
            from osprey.services.llm_service import (
                llm_configured,
                llm_not_configured_message,
            )

            # Pure request invariants come before environment/provider checks.
            # Otherwise a missing optional provider dependency can mask the
            # actual malformed request (and makes this guard impossible to test
            # without configuring an unrelated LLM).
            if req.depth > max_spawn_depth():
                raise ValueError(
                    f"Spawn depth {req.depth} exceeds cap {max_spawn_depth()} — "
                    "an agent chain nested too deep; do this work in the current agent."
                )
            if not llm_configured():
                # The direct platform_spawn_agent path (its REST endpoint turns
                # this ValueError into a clear HTTP 429 detail message) — an
                # agent job would otherwise queue, run, and only fail
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
            budget = agent_spawn_budget()
            cap = max_running_agents()
        else:
            cap = max_running_jobs()

        with self._lock:
            # Admission and insertion are one critical section.  API requests
            # can arrive on different threads, so separate running_count() calls
            # allowed two callers to observe the same free final slot and both
            # enter.  Count directly here to avoid re-entering the non-recursive
            # lock and make the configured caps exact. Constructing the record
            # under the same lock also makes its job_id numbering race-free
            # against concurrent starts of the same tool.
            record = _JobRecord(req, existing=self._jobs)
            engagement_jobs = [
                job for job in self._jobs.values()
                if job.engagement_id == req.engagement_id
            ]
            if req.kind == JobKind.INVESTIGATION_STEP:
                # Guard against a genuine in-flight duplicate (two concurrent
                # callers admitting the SAME opportunity_id while it's still
                # QUEUED/RUNNING) — never against a COMPLETED one. This used
                # to also block COMPLETED, which made ANY opportunity whose
                # tool call had ever failed permanently unrunnable for the
                # rest of the job record's lifetime: list_step()/
                # _successful_opportunity_ids() correctly keeps a FAILED
                # opportunity's id eligible (only a successful completion
                # excludes it), the driver would legitimately re-decide it,
                # and THIS guard silently 409'd every single retry forever —
                # observed live as an endless "Evidence changed; replanning"
                # loop on whichever tool happened to fail first (dnsenum,
                # gau_discovery, domain_hunter — never tool-specific). A
                # genuinely-completed-and-SUCCESSFUL opportunity is already
                # excluded before reaching here (it's simply absent from
                # current.opportunities), so dropping COMPLETED from this
                # check only restores the one thing it was silently
                # breaking: retrying a failure.
                duplicate = next(
                    (
                        job for job in engagement_jobs
                        if job.kind == JobKind.INVESTIGATION_STEP
                        and job.request.opportunity_id == req.opportunity_id
                        and job.status in (JobStatus.QUEUED, JobStatus.RUNNING)
                    ),
                    None,
                )
                if duplicate is not None:
                    raise ValueError(
                        f"Investigation opportunity already scheduled: {req.opportunity_id}"
                    )
            if req.kind == JobKind.AGENT:
                agents = [job for job in engagement_jobs if job.kind == JobKind.AGENT]
                if len(agents) >= budget:
                    raise ValueError(
                        f"Agent spawn budget exhausted ({budget}) for this engagement."
                    )
                running = sum(
                    job.status in (JobStatus.QUEUED, JobStatus.RUNNING)
                    for job in agents
                )
                if running >= cap:
                    raise ValueError(
                        f"Too many concurrent agents ({running}/{cap}). "
                        "Let one finish (platform_job_poll) before spawning more."
                    )
            else:
                running = sum(
                    job.kind != JobKind.AGENT
                    and job.status in (JobStatus.QUEUED, JobStatus.RUNNING)
                    for job in engagement_jobs
                )
                if running >= cap:
                    raise ValueError(
                        f"Too many parallel jobs ({running}/{cap}). "
                        "Poll completed jobs before starting more."
                    )
            self._jobs[record.job_id] = record
            self._prune_locked()

        # Resolve the owning event loop only once every validation check has
        # passed — the old order resolved it first, which meant a synchronous
        # caller with no loop got "no event loop" instead of the actual
        # problem (malformed request, LLM not configured, budget exhausted),
        # and made the LLM-availability guard untestable without one.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError as exc:
            with self._lock:
                self._jobs.pop(record.job_id, None)
            raise ValueError("Background jobs require an async server event loop") from exc
        record.task = loop.create_task(self._run(record.job_id), name=record.job_id)
        logger.info(
            "job spawned id=%s engagement=%s kind=%s label=%s",
            record.job_id,
            record.engagement_id,
            record.kind,
            record.label,
        )
        # Durable job history for every kind (best-effort; never blocks).
        self._persist_job(record)
        return self._to_summary(record)

    def _persist_job(self, record: _JobRecord) -> None:
        """Mirror a job's lifecycle into the durable scan_runs table (any kind —
        tool/shell/script/investigation/agent) so job state survives a restart or a
        job-store prune (_MAX_JOBS_KEPT). Previously this only ran for one
        legacy engine kind, so every AGENT job explicit callers/platform_spawn_agent
        create — and every TOOL/SHELL/SCRIPT job — vanished on restart with no
        trace; get()/get_result() fall back to this table (see _durable_summary)
        when the in-memory record is gone. Best-effort; never blocks the job."""
        try:
            from osprey.services.engagement_store import get_engagement_store
            from osprey.services.scan_run_store import get_scan_run_store

            eng = get_engagement_store().get(record.engagement_id)
            result = _serialize_result(record.result)
            get_scan_run_store().upsert(
                job_id=record.job_id,
                engagement_id=record.engagement_id,
                run_id=record.run_id,
                kind=record.kind.value,
                label=record.label,
                target=getattr(eng, "target", "") or "",
                status=record.status.value,
                max_passes=0,
                include_low_confidence=False,
                progress=record.progress,
                request=record.request.model_dump(mode="json"),
                command_preview=record.command_preview,
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
            persist = False
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
                now = time.monotonic()
                if now - rec.last_persisted_at >= 2.0:
                    rec.last_persisted_at = now
                    persist = True
            if persist:
                # A throttled heartbeat makes partial progress restart-visible
                # without turning every spinner update into a database write.
                self._persist_job(rec)

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
                    # mean the agent's task succeeded.
                    agent_ok = bool(getattr(response, "success", True))
                    record.status = JobStatus.COMPLETED if agent_ok else JobStatus.FAILED
                    if not agent_ok:
                        record.error = str(
                            getattr(response, "error", "")
                            or getattr(response, "final_message", "")
                            or "agent failed"
                        )[:2000]
                elif req.kind == JobKind.INVESTIGATION_STEP:
                    # A capability's own tool call reporting success=False (a
                    # crt.sh 502, a timed-out dnsenum, any ordinary recon
                    # hiccup) is expected, routine engine output — NOT a
                    # broken job. execute_capability() returning at all
                    # (rather than raising) means the job itself did its
                    # job: it ran the one authorized action and reported
                    # back. Marking it JobStatus.FAILED made the CLI's
                    # driver (_watch_job) treat one flaky external tool as
                    # fatal and halt the ENTIRE deterministic investigation
                    # — every subsequent opportunity silently abandoned over
                    # something as mundane as an upstream 502. The tool's
                    # own success/failure is already carried faithfully on
                    # the CapabilityResult and rendered per-opportunity
                    # (the red X card); only a real execution failure
                    # (an exception, caught below) should ever fail the job.
                    capability_ok = bool(getattr(response, "success", False))
                    record.status = JobStatus.COMPLETED
                    if not capability_ok:
                        record.error = str(getattr(response, "stopped_reason", "capability failed"))[:2000]
                else:
                    # Other bounded kinds report failure by raising or by returning
                    # ToolExecutionResponse above.
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
        if req.kind == JobKind.INVESTIGATION_STEP:
            from osprey.services.investigation_capabilities import execute_capability

            if on_progress is not None:
                on_progress(f"investigation: running {req.tool or req.capability}")
            result = await execute_capability(
                engagement_id=req.engagement_id,
                run_id=req.run_id or "",
                opportunity_id=req.opportunity_id,
                capability=req.capability,
                subject_ids=list(req.subject_ids),
                tool=req.tool,
                params=dict(req.params),
                additional_args=req.additional_args,
                timeout=req.timeout,
                capability_input=dict(req.capability_input),
                on_progress=on_progress,
            )
            if on_progress is not None:
                on_progress(
                    f"RESULT::investigation: {req.capability} "
                    f"{'completed' if result.success else 'failed'}"
                )
            return result
        if req.kind == JobKind.AGENT:
            from osprey.services import event_bus
            from osprey.services.agent_runner import run_scoped_agent

            async def _agent_progress(event: str, data: dict[str, Any]) -> None:
                # The one place a spawned phase agent's own tool calls become
                # visible: published onto the engagement's shared event bus so
                # the engagement's persistent live stream shows them inline,
                # attributed by role/job_id — not just recorded into this
                # job's own progress text (kept below for `platform_job_poll`'s
                # existing pull-style MCP contract, unrelated to this fix).
                event_bus.publish(
                    req.engagement_id, event, {**data, "job_id": job_id}, source=f"agent:{req.role}"
                )
                if on_progress is None:
                    return
                # Ephemeral "what's happening right now" (overwritten each call) —
                # Ephemeral progress is replaced by the next status update.
                if event == "tool_start":
                    on_progress(f"{req.role}: running {data.get('tool_name', '?')}")
                    return
                if event == "status":
                    on_progress(str(data.get("message", "")))
                    return
                # Persistent turn-by-turn history uses RESULT:: entries, so
                # platform_job_poll shows a
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
            elif j.kind == JobKind.INVESTIGATION_STEP:
                success = bool(getattr(j.result, "success", False))
            else:
                success = bool(getattr(j.result, "success", True))

        hint = ""
        if j.status == JobStatus.RUNNING:
            hint = "Still running — continue other work; poll later with platform_job_poll."
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
                "platform_findings / platform_priority to analyze this branch."
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
            opportunity_id=(j.request.opportunity_id if j.kind == JobKind.INVESTIGATION_STEP else ""),
            capability=(j.request.capability if j.kind == JobKind.INVESTIGATION_STEP else ""),
            driver=(j.request.driver if j.kind == JobKind.INVESTIGATION_STEP else ""),
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
