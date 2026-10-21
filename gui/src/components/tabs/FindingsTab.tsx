"use client";

import { useState } from "react";
import { Search, ShieldAlert, RefreshCw, ChevronDown } from "lucide-react";
import { getReport } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import type { Severity } from "@/lib/types";
import { SeverityPill, ConfidenceDot } from "@/components/ui/SeverityPill";
import { Loading, ErrorState } from "@/components/ui/States";
import { FindingBlock } from "./ReportTab";
import { cn } from "@/lib/cn";
import Link from "next/link";
import { RecordInspector } from "@/components/ui/RecordInspector";

export function FindingsTab({ engagementId }: { engagementId: string }) {
  const resource = useResource(
    (signal) => getReport(engagementId, signal),
    [engagementId],
  );
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [confidence, setConfidence] = useState("all");
  const [page, setPage] = useState(0);
  const [review, setReview] = useState(false);
  const [signals, setSignals] = useState(false);
  const [observation, setObservation] = useState<string | null>(null);
  if (resource.loading && !resource.loaded)
    return <Loading label="Loading security conclusions…" />;
  if (resource.error)
    return <ErrorState message={resource.error} onRetry={resource.refetch} />;
  const report = resource.data;
  const all = review
    ? report?.review_candidates || []
    : report?.findings_by_severity.flatMap((group) => group.findings) || [];
  const findings = all.filter(
    (finding) =>
      (severity === "all" || finding.severity === severity) &&
      (confidence === "all" || finding.confidence === confidence) &&
      `${finding.title} ${finding.target} ${finding.description} ${finding.id}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  return (
    <div className="mx-auto max-w-6xl p-5 md:p-7">
      <div className="mb-5 flex justify-between gap-3">
        <div>
          <p className="text-[11px] uppercase tracking-[.18em] text-amber">
            Security conclusions
          </p>
          <h2 className="mt-1 font-serif text-2xl">
            Findings to investigate and remediate
          </h2>
          <p className="mt-2 max-w-2xl text-sm text-ink-dim">
            Severity describes potential impact. Confidence describes the
            strength of the evidence. Discovery records and execution logs are
            available in Attack Surface and Evidence. Scanner signals are leads
            to investigate, with their original output available below.
          </p>
        </div>
        <button className="btn-outline self-start" onClick={resource.refetch}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>
      <div
        className="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-3"
        aria-label="Finding record categories"
      >
        {[
          {
            label: "Security conclusions",
            count: report?.totals.findings || 0,
            description: "Recorded judgments, with severity and confidence",
            active: !signals && !review,
            select: () => {
              setSignals(false);
              setReview(false);
            },
          },
          {
            label: "Scanner signals",
            count: report?.scanner_claims.length || 0,
            description: "Scanner-reported matches; inspect before concluding",
            active: signals,
            select: () => {
              setSignals(true);
              setReview(false);
            },
          },
          {
            label: "Legacy review",
            count: report?.review_candidates?.length || 0,
            description: "Older severity-tagged records retained for review",
            active: review,
            select: () => {
              setSignals(false);
              setReview(true);
            },
          },
        ].map((section) => (
          <button
            key={section.label}
            onClick={() => {
              section.select();
              setPage(0);
              setQuery("");
              setSeverity("all");
              setConfidence("all");
            }}
            className={cn(
              "rounded-xl border p-4 text-left",
              section.active
                ? "border-amber/50 bg-amber/10"
                : "border-border bg-surface",
            )}
          >
            <span className="block text-sm">{section.label}</span>
            <strong className="my-1 block text-2xl">
              {section.count.toLocaleString()}
            </strong>
            <span className="text-xs text-ink-dim">{section.description}</span>
          </button>
        ))}
      </div>
      {signals ? (
        <div>
          <p className="mb-4 text-sm text-ink-dim">
            These signals are not added to the conclusion count. Inspect the
            scanner evidence and any filed finding before judging impact or
            confidence.
          </p>
          <input
            aria-label="Search scanner signals"
            placeholder="Search signal, target or source…"
            className="mb-4 w-full rounded-lg border border-border bg-surface p-3 text-sm"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(0);
            }}
          />
          {(() => {
            const items = (report?.scanner_claims || []).filter((s) =>
              `${s.title} ${s.target} ${s.source_tool}`
                .toLowerCase()
                .includes(query.toLowerCase()),
            );
            return (
              <>
                <p className="mb-3 text-xs text-ink-faint">
                  {items.length} matching scanner signals
                </p>
                {items.slice(page * 30, (page + 1) * 30).map((s) => (
                  <article
                    key={s.observation_id}
                    className="mb-2 rounded-xl border border-border bg-surface p-4"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs uppercase text-amber">
                        Scanner claims{" "}
                        {s.scanner_claimed_severity || "unspecified severity"}
                      </span>
                      <span className="text-xs text-ink-faint">
                        {s.source_tool}
                      </span>
                    </div>
                    <h3 className="my-2 text-sm font-medium">{s.title}</h3>
                    <p className="break-all font-mono text-xs text-ink-dim">
                      {s.target}
                    </p>
                    <div className="mt-3 flex gap-3">
                      <button
                        className="btn-outline"
                        onClick={() => setObservation(s.observation_id)}
                      >
                        Inspect scanner evidence
                      </button>
                      <Link
                        className="btn-outline"
                        href={`/engagement/${encodeURIComponent(engagementId)}?tab=graph&asset=${encodeURIComponent(s.target)}`}
                      >
                        Explore target
                      </Link>
                    </div>
                  </article>
                ))}
                {items.length > 30 && (
                  <div className="flex items-center justify-end gap-3">
                    <button
                      className="btn-ghost"
                      disabled={!page}
                      onClick={() => setPage(page - 1)}
                    >
                      Previous
                    </button>
                    <span className="text-xs">
                      {page + 1} / {Math.ceil(items.length / 30)}
                    </span>
                    <button
                      className="btn-ghost"
                      disabled={(page + 1) * 30 >= items.length}
                      onClick={() => setPage(page + 1)}
                    >
                      Next
                    </button>
                  </div>
                )}
              </>
            );
          })()}
        </div>
      ) : (
        <>
          <div
            className="mb-5 flex flex-wrap gap-2"
            aria-label="Filter findings by severity"
          >
            {report?.data_limits?.possibly_partial && (
              <p className="w-full text-xs text-amber-soft">
                This summary reached a record limit. Use Evidence to inspect the
                remaining original rows.
              </p>
            )}
            {(
              [
                "all",
                "critical",
                "high",
                "medium",
                "low",
                "info",
                "none",
              ] as const
            ).map((value) => (
              <button
                key={value}
                onClick={() => {
                  setSeverity(value);
                  setPage(0);
                }}
                className={cn(
                  "rounded-xl border px-3 py-2 text-sm",
                  severity === value
                    ? "border-amber/50 bg-amber/10"
                    : "border-border bg-surface",
                )}
              >
                {value === "all" ? (
                  "All conclusions"
                ) : (
                  <SeverityPill severity={value as Severity} />
                )}{" "}
                <span className="ml-2 font-mono text-xs">
                  {value === "all"
                    ? all.length
                    : all.filter((f) => f.severity === value).length}
                </span>
              </button>
            ))}
          </div>
          <div className="mb-4 flex flex-wrap gap-3">
            <label className="flex min-w-60 flex-1 items-center gap-2 rounded-lg border border-border bg-surface px-3">
              <Search size={15} className="text-ink-faint" />
              <input
                aria-label="Search findings"
                placeholder="Search issue, affected asset, or finding ID…"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(0);
                }}
                className="w-full bg-transparent py-2.5 text-sm outline-none"
              />
            </label>
            <select
              aria-label="Finding confidence"
              className="rounded-lg border border-border bg-surface px-3 text-sm"
              value={confidence}
              onChange={(e) => {
                setConfidence(e.target.value);
                setPage(0);
              }}
            >
              <option value="all">Every confidence</option>
              <option value="confirmed">Confirmed</option>
              <option value="likely">Likely</option>
              <option value="hypothesis">Hypothesis</option>
            </select>
          </div>
          <p className="mb-3 text-xs text-ink-faint">
            {findings.length} matching{" "}
            {review
              ? "legacy review candidates — not validated conclusions"
              : "conclusions"}{" "}
            · {report?.supporting_records?.count || 0} supporting
            discovery/activity records retained separately
          </p>
          {findings.length === 0 && (
            <div className="rounded-xl border border-border p-8 text-center">
              <ShieldAlert className="mx-auto mb-3 text-ink-faint" />
              <h3 className="font-medium">No matching security conclusions</h3>
              <p className="mt-2 text-sm text-ink-dim">
                This does not establish that the target is secure. Review
                coverage and unverified signals in the report.
              </p>
            </div>
          )}
          <div className="space-y-2">
            {findings.slice(page * 30, (page + 1) * 30).map((finding) => (
              <details
                key={finding.id}
                className="group rounded-xl border border-border bg-surface/60 open:border-border-strong"
              >
                <summary className="flex cursor-pointer list-none items-start gap-3 p-4">
                  <SeverityPill severity={finding.severity} />
                  <div className="min-w-0 flex-1">
                    <h3 className="text-sm font-medium">{finding.title}</h3>
                    <p className="mt-1 break-all font-mono text-xs text-ink-faint">
                      {finding.target}
                    </p>
                  </div>
                  <ConfidenceDot confidence={finding.confidence} />
                  <ChevronDown
                    size={14}
                    className="mt-1 text-ink-faint group-open:rotate-180"
                  />
                </summary>
                <div className="border-t border-border p-3">
                  <Link
                    className="btn-outline mb-3"
                    href={`/engagement/${encodeURIComponent(engagementId)}?tab=graph&asset=${encodeURIComponent(finding.target)}`}
                  >
                    Explore affected target in graph
                  </Link>
                  <FindingBlock f={finding} engagementId={engagementId} />
                </div>
              </details>
            ))}
          </div>
          {findings.length > 30 && (
            <div className="mt-4 flex justify-end gap-3">
              <button
                className="btn-ghost"
                disabled={!page}
                onClick={() => setPage(page - 1)}
              >
                Previous
              </button>
              <span className="self-center text-xs text-ink-faint">
                Page {page + 1}
              </span>
              <button
                className="btn-ghost"
                disabled={(page + 1) * 30 >= findings.length}
                onClick={() => setPage(page + 1)}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
      {observation && (
        <RecordInspector
          engagementId={engagementId}
          records={[{ kind: "observation", id: observation }]}
          title="Scanner evidence"
          onClose={() => setObservation(null)}
        />
      )}
    </div>
  );
}
