"""JobStore query/lifecycle methods (mixin)."""

from __future__ import annotations
import asyncio
import time
from osprey.schemas.jobs import (
    JobKind,
    JobResultResponse,
    JobStatus,
    JobSummary,
)
from osprey.services.job_store._helpers import (
    _serialize_result,
    _durable_summary_from_row,
    _durable_summary,
)


class _QueryMixin:

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

    async def cancel_for_engagement(self, engagement_id: str) -> int:
        """Cancel and settle every live job owned by an engagement.

        Engagement deletion uses this before removing durable rows.  Merely
        calling ``Task.cancel()`` and immediately deleting the engagement leaves
        a race in which the task can resume at its next cancellation boundary
        and write findings/job state back under an engagement that no longer
        exists.  Waiting for all live tasks to settle closes that race.
        """
        eid = (engagement_id or "").strip()
        if not eid:
            return 0
        with self._lock:
            active_ids = [
                j.job_id
                for j in self._jobs.values()
                if j.engagement_id == eid
                and j.status in (JobStatus.QUEUED, JobStatus.RUNNING)
            ]

        tasks: list[asyncio.Task[None]] = []
        for job_id in active_ids:
            self.cancel(job_id)
            with self._lock:
                record = self._jobs.get(job_id)
                task = record.task if record is not None else None
            if task is not None and not task.done():
                tasks.append(task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return len(active_ids)

    def forget_engagement(self, engagement_id: str) -> int:
        """Drop settled process-local job records after durable deletion."""
        eid = (engagement_id or "").strip()
        if not eid:
            return 0
        with self._lock:
            job_ids = [
                job_id
                for job_id, record in self._jobs.items()
                if record.engagement_id == eid
            ]
            for job_id in job_ids:
                self._jobs.pop(job_id, None)
        return len(job_ids)

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
