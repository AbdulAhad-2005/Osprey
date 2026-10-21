"use client";

import { useEffect, useState } from "react";
import {
  cancelBackgroundJob,
  getBackgroundJobs,
  getBackgroundJobResult,
} from "@/lib/api";
import { useResource } from "@/hooks/useResource";

/** The chat Stop button only stops the driver, not independently running jobs. */
export function BackgroundJobs({
  engagementId,
  visible,
}: {
  engagementId: string;
  visible: boolean;
}) {
  const jobs = useResource(
    (signal) => getBackgroundJobs(engagementId, signal),
    [engagementId],
  );
  const [error, setError] = useState("");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const active =
    jobs.data?.filter((job) => ["running", "queued"].includes(job.status)) ||
    [];
  useEffect(() => {
    if (!visible) return;
    const timer = setInterval(
      () => {
        if (document.visibilityState !== "hidden" && !jobs.loading)
          jobs.refetch();
      },
      active.length ? 4000 : 15000,
    );
    return () => clearInterval(timer);
  }, [visible, active.length, jobs.loading, jobs.refetch]);
  if (!jobs.data?.length && !jobs.error) return null;
  async function cancel(id: string) {
    setError("");
    try {
      await cancelBackgroundJob(id);
      jobs.refetch();
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Could not cancel the job.",
      );
    }
  }
  async function inspect(id: string) {
    setError("");
    try {
      setResult(await getBackgroundJobResult(id));
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Could not load the result.",
      );
    }
  }
  return (
    <details
      className="mb-5 rounded-xl border border-border bg-surface/60 p-3"
      open={active.length > 0 || undefined}
    >
      <summary className="cursor-pointer text-xs font-semibold text-ink-dim">
        Background jobs · {active.length} active · latest{" "}
        {jobs.data?.length || 0} records
      </summary>
      <p className="mt-2 text-xs text-ink-faint">
        Stopping chat does not cancel independent jobs. Inspect their
        progress/results or cancel a specific job here. Latest 20 jobs are
        shown.
      </p>
      {(error || jobs.error) && (
        <p role="alert" className="mt-2 break-all text-xs text-sev-high">
          {error || jobs.error}
        </p>
      )}
      <div className="mt-3 space-y-2">
        {jobs.data?.map((job) => (
          <section
            key={job.job_id}
            className="rounded-lg border border-border p-3"
          >
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <strong className="break-all">
                {job.label || job.tool_name || job.job_id}
              </strong>
              <span className="ml-auto text-ink-faint">{job.status}</span>
              {["running", "queued"].includes(job.status) && (
                <button
                  className="btn-outline text-xs"
                  onClick={() => void cancel(job.job_id)}
                >
                  Cancel job
                </button>
              )}
              <button
                className="btn-ghost text-xs"
                onClick={() => void inspect(job.job_id)}
              >
                Inspect result
              </button>
            </div>
            {job.command_preview && (
              <p className="mt-1 break-all font-mono text-[11px] text-ink-faint">
                {job.command_preview}
              </p>
            )}
            {job.progress && (
              <p className="mt-2 whitespace-pre-wrap text-xs text-ink-dim">
                {job.progress}
              </p>
            )}
            {job.error && (
              <p className="mt-2 whitespace-pre-wrap text-xs text-sev-high">
                {job.error}
              </p>
            )}
            {!!job.results_log?.length && (
              <details className="mt-2">
                <summary className="cursor-pointer text-xs text-ink-faint">
                  Progress log · {job.results_log.length} entries
                </summary>
                <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all text-xs text-ink-dim">
                  {job.results_log.join("\n")}
                </pre>
              </details>
            )}
          </section>
        ))}
      </div>
      {result && (
        <section className="mt-3">
          <button
            className="btn-ghost mb-2 text-xs"
            onClick={() => setResult(null)}
          >
            Close result
          </button>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
            {JSON.stringify(result, null, 2)}
          </pre>
        </section>
      )}
    </details>
  );
}
