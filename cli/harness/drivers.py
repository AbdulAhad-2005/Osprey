from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from cli.agent.context import build_system_prompt, summarize_last_action
from cli.agent.llm import CLIModelConfig
from cli.agent.loop import Event, Runner

if TYPE_CHECKING:
    from cli.harness.runtime import HarnessRuntime


EventSink = Callable[[Event], None]

# A stale-revision (409) response means "the world moved between sense and
# act — recompute and retry," which is a normal, expected outcome of
# optimistic concurrency and needs no cap under ordinary conditions (the
# retry immediately sees fresh state and either succeeds or picks a
# different opportunity). But an optimistic-concurrency retry loop with NO
# ceiling is a latent hang by construction: if the same opportunity keeps
# losing the race turn after turn (observed live: crt_sh_query replanning
# nonstop against geo.tv), the loop has no way to ever stop on its own.
# Bounded + backed off so a real conflict resolves quickly, and a
# persistent one surfaces as a clear, actionable stop instead of an
# unbounded silent spin.
_MAX_CONSECUTIVE_STALE = 8


class LLMDriver:
    """The model-backed driver for the CLI harness.

    Runner remains the low-level ReAct implementation.  Lifecycle, binding,
    mode changes, context refresh, and event delivery belong here so every CLI
    entry point uses the same driver instance.
    """

    name = "llm"

    def __init__(self, runtime: "HarnessRuntime") -> None:
        self.runtime = runtime
        self.runner: Runner | None = None

    def reset(self) -> None:
        if self.runner is not None:
            self.runner.reset()
        self.runner = None

    def _runner(self) -> Runner:
        if self.runner is not None:
            return self.runner
        config = CLIModelConfig.from_env()
        agent = self.runtime.session.active_agent
        tool_filter = None
        if agent is not None:
            if agent.model:
                from dataclasses import replace

                config = replace(config, model=agent.model)
            tool_filter = agent.tool_allowed
        self.runner = Runner(
            config=config,
            api_base_url=self.runtime.base_url,
            engagement_id=self.runtime.active_engagement_id or "",
            target=self.runtime.active_target or "",
            tool_filter=tool_filter,
            agent_prompt=(agent.prompt if agent is not None else ""),
            tool_gateway=self.runtime.tool_gateway,
            worker_factory=self.runtime.workers.create,
        )
        return self.runner

    async def drive(self, prompt: str, sink: EventSink) -> bool:
        runner = self._runner()
        agent = self.runtime.session.active_agent
        system_prompt = await build_system_prompt(
            self.runtime.active_engagement_id or "",
            tool_budget_active=runner.config.tool_schema_budget_tokens > 0,
            agent_prompt=(agent.prompt if agent is not None else ""),
            last_action=summarize_last_action(runner.messages),
            tool_caller=self.runtime.tool_gateway.call,
        )
        succeeded = True
        async for event in runner.run(prompt, system_prompt=system_prompt):
            if event.type == "error":
                succeeded = False
            elif event.type == "done" and str(event.data.get("content") or "").startswith(
                "(stopped:"
            ):
                succeeded = False
            sink(event)
        return succeeded


@dataclass(frozen=True)
class JobEvent:
    """A domain-neutral event emitted by a backend execution job."""

    type: str
    data: dict[str, Any]


@dataclass(frozen=True)
class Opportunity:
    """One opaque backend-proposed capability opportunity.

    The CLI may rank these generic records, but it never interprets capability
    names, targets, ports, finding types, or parameters.
    """

    id: str
    capability: str = ""
    label: str = ""
    rationale: str = ""
    priority: float = 0.0
    independent_group: str = ""
    execution_mode: str = "job"
    approval_required: bool = False
    risk: str = ""
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "Opportunity":
        subjects = payload.get("subjects") or []
        subject_labels = [
            str(item.get("label") or item.get("asset_id") or "").strip()
            for item in subjects
            if isinstance(item, dict)
        ]
        subject_labels = [item for item in subject_labels if item]
        subject_label = ", ".join(subject_labels[:3])
        if len(subject_labels) > 3:
            subject_label += f" (+{len(subject_labels) - 3} more)"
        return cls(
            id=str(payload.get("id") or payload.get("opportunity_id") or ""),
            capability=str(payload.get("capability") or ""),
            label=str(
                payload.get("display_label")
                or payload.get("label")
                or payload.get("title")
                or subject_label
                or payload.get("capability")
                or ""
            ),
            rationale=str(payload.get("rationale") or payload.get("reason") or ""),
            priority=float(payload.get("priority") or 0.0),
            independent_group=str(payload.get("independent_group") or ""),
            execution_mode=str(payload.get("execution_mode") or "job"),
            approval_required=bool(payload.get("approval_required", False)),
            risk=str(payload.get("risk") or ""),
            raw=dict(payload),
        )


@dataclass(frozen=True)
class InvestigationStep:
    engagement_id: str
    run_id: str
    revision: str
    status: str
    state_summary: Any
    opportunities: tuple[Opportunity, ...]
    active_jobs: tuple[dict[str, Any], ...]

    @classmethod
    def from_payload(
        cls, payload: dict[str, Any], *, engagement_id: str, run_id: str
    ) -> "InvestigationStep":
        return cls(
            engagement_id=engagement_id,
            run_id=str(payload.get("run_id") or run_id),
            revision=str(payload.get("revision") or ""),
            status=str(payload.get("status") or "ready"),
            state_summary=payload.get("state_summary") or "",
            opportunities=tuple(
                Opportunity.from_payload(item)
                for item in (payload.get("opportunities") or [])
                if isinstance(item, dict)
            ),
            active_jobs=tuple(
                dict(item)
                for item in (payload.get("active_jobs") or [])
                if isinstance(item, dict)
            ),
        )


@dataclass(frozen=True)
class Decision:
    opportunity_id: str
    expected_revision: str
    driver: str
    rationale: str


class CapabilityJobDriver:
    """Lifecycle adapter for an explicitly selected backend utility job.

    This is intentionally not investigation intelligence. It remains for direct
    operator utilities such as fast-scan.
    """

    name = "capability-job"

    def __init__(self, runtime: "HarnessRuntime") -> None:
        self.runtime = runtime

    def drive_job(
        self,
        *,
        starter: Callable[[], dict[str, Any]],
        wait_seconds: int = 3,
    ):
        job = starter()
        job_id = str(job.get("job_id") or "")
        if not job_id:
            yield JobEvent("error", {"message": "Backend did not return a job id."})
            return

        yield JobEvent("job_started", {"job_id": job_id, "job": job})
        printed_results = 0
        last_progress = ""
        try:
            while str(job.get("status") or "") in {"queued", "running"}:
                job = self.runtime.client.poll_job(job_id, wait_seconds=wait_seconds)
                results = job.get("results_log") or []
                for line in results[printed_results:]:
                    yield JobEvent("job_log", {"job_id": job_id, "line": line})
                printed_results = len(results)
                progress = str(job.get("progress") or "")
                if progress and progress != last_progress:
                    last_progress = progress
                    yield JobEvent("job_progress", {"job_id": job_id, "progress": progress})
        except KeyboardInterrupt:
            self.runtime.client.cancel_job(job_id)
            yield JobEvent("job_cancelled", {"job_id": job_id})
            return

        status = str(job.get("status") or "")
        if status == "failed":
            yield JobEvent(
                "error",
                {"job_id": job_id, "message": str(job.get("error") or "unknown error")},
            )
            return
        if status == "cancelled":
            yield JobEvent("job_cancelled", {"job_id": job_id})
            return
        result = self.runtime.client.job_result(job_id)
        yield JobEvent("job_completed", {"job_id": job_id, "job": job, "result": result})


class InvestigationDriver:
    """Domain-neutral sense-decide-act loop over backend opportunities."""

    name = "investigation"
    terminal_statuses = frozenset({"complete", "completed", "exhausted"})

    def __init__(self, runtime: "HarnessRuntime") -> None:
        self.runtime = runtime

    def decide(self, step: InvestigationStep) -> Decision | None:
        raise NotImplementedError

    def _sense(self) -> InvestigationStep:
        engagement_id = self.runtime.active_engagement_id
        if not engagement_id:
            raise RuntimeError("No engagement bound.")
        state = self.runtime.session.investigation
        payload = self.runtime.client.investigation_step(
            engagement_id, run_id=state.run_id
        )
        step = InvestigationStep.from_payload(
            payload, engagement_id=engagement_id, run_id=state.run_id
        )
        state.run_id = step.run_id
        state.revision = step.revision
        return step

    # Mirrors config/parallelism.yaml::max_running_jobs (backend default 4) —
    # the backend caps concurrent INVESTIGATION_STEP jobs there, so the driver
    # launches at most this many at once and a launch is never rejected for the
    # cap. A fat-fingered backend value only ever LOWERS the real ceiling (the
    # backend enforces its own), never raises it.
    _MAX_CONCURRENT = 4

    def _reap_active(self, active: dict, wait_seconds: int):
        """One non-blocking (wait_seconds=0) pass over in-flight jobs: stream any
        new log lines, and for any job that has FINISHED yield its terminal
        event and drop it from ``active``. A still-running job simply stays in
        ``active`` across iterations — running in the background while other work
        proceeds — and is NEVER cancelled for being slow (plan 19 Part B: slow is
        not broken). A ``wait_seconds > 0`` blocks briefly on each polled job so
        the caller can wait for progress instead of busy-spinning."""
        state = self.runtime.session.investigation
        for job_id in list(active):
            info = active[job_id]
            job = self.runtime.client.poll_job(job_id, wait_seconds=wait_seconds)
            results = job.get("results_log") or []
            printed = int(info.get("printed_results", 0))
            for line in results[printed:]:
                yield JobEvent("capability_log", {"job_id": job_id, "line": line})
            info["printed_results"] = len(results)
            status = str(job.get("status") or "")
            if status in {"queued", "running"}:
                continue
            active.pop(job_id, None)
            state.active_job_id = next(iter(active), "")
            if status == "cancelled":
                state.status = "cancelled"
                yield JobEvent("cancelled", {"job_id": job_id})
                return
            if status == "failed":
                # A failed JOB (distinct from a tool timeout — those return as a
                # completed capability whose result marks the tool timed_out):
                # surface it as a capability_completed carrying the failure, so
                # the renderer shows one tool card, not a separate error line.
                yield JobEvent("capability_completed", {
                    "job_id": job_id, "opportunity_id": info.get("opportunity_id", ""),
                    "result": {"result": {"details": {"results": [{
                        "tool": info.get("tool", ""), "success": False,
                        "error": str(job.get("error") or "job failed"),
                    }]}}},
                })
            else:
                result = self.runtime.client.job_result(job_id)
                yield JobEvent("capability_completed", {
                    "job_id": job_id, "opportunity_id": info.get("opportunity_id", ""),
                    "job": job, "result": result,
                })

    def drive(self, *, wait_seconds: int = 3):
        """Background-and-continue scheduler (plan 19 Part B).

        Instead of running one tool to completion before starting the next, this
        launches up to ``_MAX_CONCURRENT`` opportunities at once and REAPS them
        as they finish. A slow tool runs in the background while other
        independent work proceeds, and is never killed for being slow — the tool
        budget is now just a generous safety ceiling. This is how a real
        operator (and Claude Code) works: fan out, keep moving, collect results
        as they land. Each loop: reap finished jobs → re-sense → launch up to the
        cap → (if nothing new to launch but jobs are in flight) block briefly on
        one so we don't busy-spin, then loop. Reaching a fixpoint — no in-flight
        jobs and no launchable opportunity — ends the run.
        """
        state = self.runtime.session.investigation
        state.status = "running"
        active: dict[str, dict] = {}
        stale_opportunity_id = ""
        stale_count = 0
        try:
            while True:
                if state.status == "paused":
                    yield JobEvent("paused", {"job_id": next(iter(active), "")})
                    return
                if state.status == "cancelled":
                    yield JobEvent("cancelled", {"job_id": next(iter(active), "")})
                    return

                # 1. Reap finished jobs without blocking.
                yield from self._reap_active(active, 0)
                if state.status == "cancelled":
                    yield JobEvent("cancelled", {"job_id": next(iter(active), "")})
                    return

                # 2. Sense fresh state, adopting any server-side job we aren't
                #    tracking yet (e.g. /resume reattaching a job left running).
                step = self._sense()
                for aj in step.active_jobs:
                    jid = str(aj.get("job_id") or "")
                    if jid and jid not in active and str(aj.get("status") or "") in {"queued", "running"}:
                        rtool = str(aj.get("tool_name") or "")
                        rtool = "" if rtool.startswith("investigation:") else rtool
                        # Key an adopted job by its own id (it has no decision in
                        # this session), so its completion matches back to this
                        # start card.
                        active[jid] = {"opportunity_id": jid, "tool": rtool, "printed_results": 0}
                        state.active_job_id = jid
                        yield JobEvent("capability_started", {
                            "job_id": jid, "opportunity_id": jid, "resumed": True, "tool": rtool,
                        })
                yield JobEvent("state", {
                    "revision": step.revision, "status": step.status,
                    "state_summary": step.state_summary,
                })
                yield JobEvent("opportunities", {
                    "revision": step.revision,
                    "opportunities": [item.raw for item in step.opportunities],
                })

                active_opp_ids = {i["opportunity_id"] for i in active.values() if i.get("opportunity_id")}
                launchable = [o for o in step.opportunities if o.id and o.id not in active_opp_ids]

                # 3. Fixpoint: nothing running and nothing to launch.
                if not active and not launchable:
                    if step.status.lower() in self.terminal_statuses:
                        state.status = "complete"
                        yield JobEvent("complete", {
                            "revision": step.revision, "state_summary": step.state_summary,
                        })
                        return
                    event_type = "waiting" if step.status.lower() == "waiting" else "blocked"
                    state.status = event_type
                    yield JobEvent(event_type, {
                        "revision": step.revision, "state_summary": step.state_summary,
                    })
                    return

                # 4. Launch up to the concurrency cap. Re-sense after each launch
                #    so the next one uses a fresh revision (active_jobs changed) —
                #    this is what keeps concurrent launches from 409-ing each
                #    other under the backend's optimistic-concurrency check.
                launched_any = False
                while len(active) < self._MAX_CONCURRENT and launchable:
                    selected = max(launchable, key=lambda item: item.priority)
                    rationale = selected.rationale or (
                        f"highest backend-ranked opportunity (priority {selected.priority:g})"
                    )
                    tool = str(selected.raw.get("tool") or "")
                    params = dict(selected.raw.get("params") or {})
                    state.active_opportunity_id = selected.id
                    yield JobEvent("decision", {
                        "revision": step.revision, "opportunity_id": selected.id,
                        "capability": selected.capability, "label": selected.label,
                        "priority": selected.priority, "rationale": rationale,
                        "driver": self.name, "tool": tool, "params": params,
                    })
                    try:
                        response = self.runtime.client.execute_investigation_step(
                            engagement_id=step.engagement_id, run_id=step.run_id,
                            opportunity_id=selected.id, expected_revision=step.revision,
                            driver=self.name, rationale=rationale,
                        )
                    except Exception as exc:
                        response_obj = getattr(exc, "response", None)
                        sc = getattr(response_obj, "status_code", None)
                        if sc == 429:
                            # Backend concurrency/budget cap reached — stop
                            # launching this pass, let in-flight jobs drain.
                            break
                        if sc == 409:
                            state.active_opportunity_id = ""
                            if selected.id == stale_opportunity_id:
                                stale_count += 1
                            else:
                                stale_opportunity_id = selected.id
                                stale_count = 1
                            diff = ""
                            try:
                                detail = (response_obj.json() or {}).get("detail")
                                diff = str(detail.get("diff") or "") if isinstance(detail, dict) else str(detail or "")
                            except Exception:  # noqa: BLE001
                                pass
                            if stale_count > _MAX_CONSECUTIVE_STALE:
                                state.status = "blocked"
                                yield JobEvent("error", {"message": (
                                    f"{selected.label or selected.id} kept losing the replan race "
                                    f"{stale_count} times in a row — stopping instead of retrying "
                                    "forever. Use /resume to try again."
                                    + (f" Last diff: {diff}" if diff else "")
                                )})
                                return
                            yield JobEvent("state_stale", {
                                "revision": step.revision,
                                "message": "Evidence changed before scheduling; replanning.",
                            })
                            time.sleep(min(0.25 * stale_count, 2.0))
                            break  # re-sense on the next outer iteration
                        raise
                    stale_opportunity_id = ""
                    stale_count = 0
                    job = response.get("job") or {}
                    job_id = str(job.get("job_id") or response.get("job_id") or "")
                    if not job_id:
                        yield JobEvent("error", {
                            "message": "Selected capability did not return a durable job id.",
                            "decision": response.get("decision") or {},
                        })
                        return
                    active[job_id] = {"opportunity_id": selected.id, "tool": tool, "printed_results": 0}
                    state.active_job_id = job_id
                    yield JobEvent("capability_started", {
                        "job_id": job_id, "opportunity_id": selected.id,
                        "capability": selected.capability, "tool": tool, "params": params,
                    })
                    launched_any = True
                    step = self._sense()
                    active_opp_ids = {i["opportunity_id"] for i in active.values() if i.get("opportunity_id")}
                    launchable = [o for o in step.opportunities if o.id and o.id not in active_opp_ids]

                # 5. If we couldn't launch anything but work is in flight, wait
                #    briefly on one job (don't busy-spin); then loop → reap.
                if active and not launched_any:
                    oldest = next(iter(active))
                    try:
                        self.runtime.client.poll_job(oldest, wait_seconds=wait_seconds)
                    except Exception:  # noqa: BLE001 — reaped/handled next iteration
                        pass
                elif not active and not launched_any:
                    # launchable existed but every launch 409'd/429'd — small
                    # pause before re-sensing, so we don't tight-loop.
                    time.sleep(0.2)
        except KeyboardInterrupt:
            state.status = "paused"
            yield JobEvent("paused", {"job_id": next(iter(active), "")})


class DeterministicInvestigationDriver(InvestigationDriver):
    """Select only the backend's highest-priority returned opportunity."""

    name = "deterministic"

    def decide(self, step: InvestigationStep) -> Decision | None:
        candidates = [item for item in step.opportunities if item.id]
        if not candidates:
            return None
        selected = max(candidates, key=lambda item: item.priority)
        rationale = selected.rationale or (
            f"highest backend-ranked opportunity (priority {selected.priority:g})"
        )
        return Decision(
            opportunity_id=selected.id,
            expected_revision=step.revision,
            driver=self.name,
            rationale=rationale,
        )


# There is deliberately no LLM-driven investigation opportunity picker here.
# An earlier design (LLMOpportunityDriver) let a real LLM choose only one
# opaque opportunity id per turn from a server-computed menu — "add model
# judgment without giving the model a second control plane." That was the
# anti-pattern: it took away exactly the tool-by-tool reasoning an LLM
# already does natively (see cli/agent/loop.py's Runner, used directly by
# LLMDriver above) and replaced it with a constrained multiple-choice
# question. A real LLM operator should call the typed recon/vuln/exploit
# tools directly — via LLMDriver's ReAct loop, guided by AGENTS.md's
# methodology and platform_priority/platform_context as advisory signals —
# exactly like it already does for vuln/exploit work. DeterministicInvestig
# ationDriver above remains the *only* opportunity-picking driver, reserved
# for the genuinely no-LLM baseline (no API key configured), where code has
# to supply the judgment because there is no model to have any.


class SupervisedDeterministicDriver:
    """The "blanket over a person": the deterministic engine (the person) runs
    itself, unattended, spending zero LLM tokens on the obvious mechanical
    pentest work. An LLM, when configured, wraps around it (the blanket) and
    checks in only at bounded checkpoints — not per opportunity, which would
    recreate the LLMOpportunityDriver anti-pattern above at a different
    frequency.

    The critical design choice: at a checkpoint the LLM is handed to
    ``LLMDriver`` exactly as if the operator had typed a prompt directly — the
    SAME unrestricted ReAct loop, the full tool catalog, no constrained
    action schema. It can run any tool, file a finding, redirect priorities
    by acting on the graph directly, or do nothing and let the deterministic
    loop continue — whatever it judges the situation calls for. There is no
    narrower "redirect hint" primitive here on purpose: inventing one would
    just be a smaller version of the same mistake — taking a decision the
    LLM is fully equipped to make itself and routing it through a constrained
    interface instead.
    """

    name = "supervised"

    def __init__(self, runtime: "HarnessRuntime", *, checkpoint_every: int = 10) -> None:
        self.runtime = runtime
        self.checkpoint_every = checkpoint_every
        self._completed_since_checkpoint = 0
        self._seen_notable_finding_ids: set[str] = set()

    def drive(self):
        state = self.runtime.session.investigation
        for event in self.runtime.deterministic.drive():
            yield event
            if event.type == "capability_completed":
                self._completed_since_checkpoint += 1
            if state.status in {"paused", "cancelled", "blocked", "waiting"}:
                # The deterministic loop already stopped scheduling (out of
                # opportunities, or the operator paused/cancelled) — a
                # checkpoint here would consult the LLM on a loop that isn't
                # going to resume by itself, which is what /scan's own
                # 'nothing left, check in' step already does at the CLI layer.
                return
            reason = self._checkpoint_reason()
            if reason:
                self._completed_since_checkpoint = 0
                yield from self._run_checkpoint(reason)

    def _checkpoint_reason(self) -> str:
        if self._completed_since_checkpoint >= self.checkpoint_every:
            return f"{self.checkpoint_every} opportunities completed since the last checkpoint"
        new_notable = self._new_notable_findings()
        if new_notable:
            return "new high-severity finding(s): " + ", ".join(new_notable)
        return ""

    def _new_notable_findings(self) -> list[str]:
        engagement_id = self.runtime.active_engagement_id
        if not engagement_id:
            return []
        try:
            findings = self.runtime.client.list_findings(engagement_id, limit=200)
        except Exception:
            return []
        titles: list[str] = []
        for f in findings:
            fid = str(f.get("id") or "")
            severity = str(f.get("claim_severity") or "").lower()
            if fid and fid not in self._seen_notable_finding_ids and severity in {"critical", "high"}:
                self._seen_notable_finding_ids.add(fid)
                titles.append(str(f.get("title") or fid))
        return titles

    def _run_checkpoint(self, reason: str):
        yield JobEvent("checkpoint_started", {"reason": reason})
        buffered: list[Event] = []
        prompt = (
            f"Checkpoint ({reason}). The deterministic engine has been running this "
            "engagement unattended. Look at the current state (platform_context/"
            "platform_priority/platform_anomalies) and act on anything you judge "
            "worth it — investigate a lead, file a finding, run a deeper probe, "
            "reprioritize by working the graph directly — using the full tool "
            "catalog, exactly as you would driving this engagement yourself. If "
            "nothing here needs your attention right now, say so briefly; the "
            "deterministic engine resumes either way."
        )
        try:
            succeeded = self.runtime.drive_prompt(prompt, buffered.append)
        except Exception as exc:  # noqa: BLE001 — a checkpoint failure must never wedge the deterministic loop
            yield JobEvent("checkpoint_completed", {"reason": reason, "succeeded": False, "error": str(exc)[:300]})
            return
        for ev in buffered:
            yield JobEvent("checkpoint_llm_event", {"type": ev.type, "data": ev.data})
        yield JobEvent("checkpoint_completed", {"reason": reason, "succeeded": succeeded})
