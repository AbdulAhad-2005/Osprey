"use client";

import { useState } from "react";
import { Search, ShieldAlert, RefreshCw, ChevronDown, Radar, History, Crosshair, ExternalLink } from "lucide-react";
import Link from "next/link";
import { getReport } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import type { ReportData, Severity } from "@/lib/types";
import { SEVERITY_META } from "@/lib/format";
import { SeverityPill, ConfidenceDot } from "@/components/ui/SeverityPill";
import { Loading, ErrorState } from "@/components/ui/States";
import { Page, Card, StatTile, Segmented, Chip } from "@/components/ui/primitives";
import { Donut, type DonutSegment } from "@/components/ui/Donut";
import { RecordInspector } from "@/components/ui/RecordInspector";
import { FindingBlock } from "./ReportTab";
import { cn } from "@/lib/cn";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info", "none"];
type View = "conclusions" | "signals" | "legacy";

export function FindingsTab({ engagementId }: { engagementId: string }) {
  const resource = useResource((signal) => getReport(engagementId, signal), [engagementId]);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [confidence, setConfidence] = useState("all");
  const [page, setPage] = useState(0);
  const [view, setView] = useState<View>("conclusions");
  const [observation, setObservation] = useState<string | null>(null);
  if (resource.loading && !resource.loaded) return <Loading label="Loading security conclusions…" />;
  if (resource.error) return <ErrorState message={resource.error} onRetry={resource.refetch} />;

  const report = resource.data;
  const review = view === "legacy";
  const all = review
    ? report?.review_candidates || []
    : report?.findings_by_severity.flatMap((group) => group.findings) || [];
  const findings = all.filter(
    (finding) =>
      (severity === "all" || finding.severity === severity) &&
      (confidence === "all" || finding.confidence === confidence) &&
      `${finding.title} ${finding.target} ${finding.description} ${finding.id}`.toLowerCase().includes(query.toLowerCase()),
  );

  function switchView(next: View) {
    setView(next);
    setPage(0);
    setQuery("");
    setSeverity("all");
    setConfidence("all");
  }

  const sev = report?.totals.by_severity ?? {};
  const headline = sev.critical ? `${sev.critical} ${sev.critical === 1 ? "is" : "are"} critical.` : sev.high ? `${sev.high} ${sev.high === 1 ? "is" : "are"} high severity.` : "None are critical or high.";
  const sevSegments: DonutSegment[] = (["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => ({
    key: s,
    label: SEVERITY_META[s].label,
    value: all.filter((f) => f.severity === s).length,
    dot: SEVERITY_META[s].dot,
    color: `rgb(var(--c-sev-${s}))`,
  }));
  const topTargets = Object.entries(
    all.reduce<Record<string, number>>((acc, f) => ({ ...acc, [f.target]: (acc[f.target] || 0) + 1 }), {}),
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <Page
      eyebrow="Security conclusions"
      title={`${(report?.totals.findings || 0).toLocaleString()} findings to review.`}
      subtitle={headline}
      description="Severity describes potential impact; confidence describes the strength of the evidence. Scanner signals are leads to investigate, not conclusions."
      actions={
        <button className="btn-outline" onClick={resource.refetch}>
          <RefreshCw size={14} /> Refresh
        </button>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          icon={ShieldAlert}
          tone="critical"
          label="Critical + High"
          value={(sev.critical || 0) + (sev.high || 0)}
          sub="Highest-impact conclusions"
        />
        <StatTile
          icon={Crosshair}
          tone="accent"
          label="Security conclusions"
          value={report?.totals.findings || 0}
          sub="Judgments with severity & confidence"
          active={view === "conclusions"}
          onClick={() => switchView("conclusions")}
        />
        <StatTile
          icon={Radar}
          tone="warn"
          label="Scanner signals"
          value={report?.scanner_claims.length || 0}
          sub="Unverified scanner matches"
          active={view === "signals"}
          onClick={() => switchView("signals")}
        />
        <StatTile
          icon={History}
          tone="neutral"
          label="Legacy review"
          value={report?.review_candidates?.length || 0}
          sub="Older severity-tagged records"
          active={view === "legacy"}
          onClick={() => switchView("legacy")}
        />
      </div>

      {report?.data_limits?.possibly_partial && (
        <p className="rounded-lg border border-warn/30 bg-warn/[0.07] px-3 py-2 text-[12.5px] text-warn">
          This summary reached a record limit. Use Evidence to inspect the remaining original rows.
        </p>
      )}

      {view === "signals" ? (
        <SignalsView
          engagementId={engagementId}
          claims={report?.scanner_claims || []}
          query={query}
          setQuery={(q) => {
            setQuery(q);
            setPage(0);
          }}
          page={page}
          setPage={setPage}
          onInspect={setObservation}
        />
      ) : (
        <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div className="min-w-0 space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <Segmented
              label="Filter findings by severity"
              value={severity}
              onChange={(v) => {
                setSeverity(v);
                setPage(0);
              }}
              options={[
                { value: "all", label: "All", count: all.length },
                ...SEVERITIES.filter((s) => s !== "none" || all.some((f) => f.severity === "none")).map((s) => ({
                  value: s,
                  label: (
                    <span className="inline-flex items-center gap-1.5">
                      <span className={cn("h-2 w-2 rounded-full", SEVERITY_META[s].dot)} />
                      {SEVERITY_META[s].label}
                    </span>
                  ),
                  count: all.filter((f) => f.severity === s).length,
                })),
              ]}
            />
            <label className="flex min-w-60 flex-1 items-center gap-2 rounded-lg border border-border bg-surface px-3 shadow-card focus-within:border-accent/60 focus-within:shadow-focus">
              <Search size={15} className="text-ink-faint" />
              <input
                aria-label="Search findings"
                placeholder="Search issue, affected asset, or finding ID…"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(0);
                }}
                className="w-full bg-transparent py-2 text-[13px] outline-none placeholder:text-ink-faint"
              />
            </label>
            <select
              aria-label="Finding confidence"
              className="rounded-lg border border-border bg-surface px-3 py-2 text-[13px] shadow-card"
              value={confidence}
              onChange={(e) => {
                setConfidence(e.target.value);
                setPage(0);
              }}
            >
              <option value="all">Any confidence</option>
              <option value="confirmed">Confirmed</option>
              <option value="likely">Likely</option>
              <option value="hypothesis">Hypothesis</option>
            </select>
          </div>

          <p className="-mt-2 text-[12px] text-ink-faint">
            {findings.length} matching {review ? "legacy review candidates — not validated conclusions" : "conclusions"} ·{" "}
            {report?.supporting_records?.count || 0} supporting discovery/activity records retained separately
          </p>

          {findings.length === 0 && (
            <Card>
              <div className="py-8 text-center">
                <ShieldAlert className="mx-auto mb-3 text-ink-faint" />
                <h3 className="font-medium text-ink">No matching security conclusions</h3>
                <p className="mx-auto mt-2 max-w-md text-[13px] text-ink-dim">
                  This does not establish that the target is secure. Review coverage and unverified signals in the report.
                </p>
              </div>
            </Card>
          )}

          <div className="space-y-2.5">
            {findings.slice(page * 30, (page + 1) * 30).map((finding) => (
              <details
                key={finding.id}
                className="group relative overflow-hidden rounded-xl border border-border bg-surface shadow-card transition-shadow open:shadow-lift hover:border-border-strong"
              >
                <span className={cn("absolute inset-y-0 left-0 w-1", SEVERITY_META[finding.severity].dot)} />
                <summary className="flex cursor-pointer list-none items-center gap-3 py-3.5 pl-5 pr-4">
                  <SeverityPill severity={finding.severity} />
                  <div className="min-w-0 flex-1">
                    <h3 className="text-[14px] font-semibold text-ink">{finding.title}</h3>
                    <p className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-ink-faint">
                      <span className="break-all font-mono">{finding.target}</span>
                      {finding.type && <Chip>{finding.type.replace(/_/g, " ")}</Chip>}
                    </p>
                  </div>
                  <ConfidenceDot confidence={finding.confidence} />
                  <ChevronDown size={16} className="text-ink-faint transition-transform group-open:rotate-180" />
                </summary>
                <div className="border-t border-border bg-surface-2 p-4 pl-5">
                  <Link
                    className="btn-outline mb-3 text-[12.5px]"
                    href={`/engagement/${encodeURIComponent(engagementId)}?tab=graph&asset=${encodeURIComponent(finding.target)}`}
                  >
                    <ExternalLink size={13} /> Explore affected target in graph
                  </Link>
                  <FindingBlock f={finding} engagementId={engagementId} embedded />
                </div>
              </details>
            ))}
          </div>
          <Pager page={page} setPage={setPage} total={findings.length} size={30} />
          </div>
          <aside className="space-y-6">
            <Card title="Severity distribution">
              <Donut
                segments={sevSegments}
                active={severity === "all" ? undefined : severity}
                onSelect={(k) => {
                  setSeverity(severity === k ? "all" : (k as Severity));
                  setPage(0);
                }}
              />
            </Card>
            {topTargets.length > 0 && (
              <Card title="Most affected assets">
                <ul className="space-y-3.5">
                  {topTargets.map(([target, count]) => (
                    <li key={target}>
                      <div className="flex items-center justify-between gap-3 text-[12.5px]">
                        <span className="truncate font-mono text-ink-dim" title={target}>{target || "—"}</span>
                        <b className="tabular-nums text-ink">{count}</b>
                      </div>
                      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-3">
                        <div className="h-full rounded-full bg-gradient-to-r from-accent to-[#7fb0ff]" style={{ width: `${(100 * count) / topTargets[0]![1]}%` }} />
                      </div>
                    </li>
                  ))}
                </ul>
              </Card>
            )}
          </aside>
        </div>
      )}

      {observation && (
        <RecordInspector
          engagementId={engagementId}
          records={[{ kind: "observation", id: observation }]}
          title="Scanner evidence"
          onClose={() => setObservation(null)}
        />
      )}
    </Page>
  );
}

function Pager({ page, setPage, total, size }: { page: number; setPage: (n: number) => void; total: number; size: number }) {
  if (total <= size) return null;
  return (
    <div className="flex items-center justify-end gap-3">
      <button className="btn-outline" disabled={!page} onClick={() => setPage(page - 1)}>
        Previous
      </button>
      <span className="text-xs text-ink-faint">
        Page {page + 1} of {Math.ceil(total / size)}
      </span>
      <button className="btn-outline" disabled={(page + 1) * size >= total} onClick={() => setPage(page + 1)}>
        Next
      </button>
    </div>
  );
}

function SignalsView({
  engagementId,
  claims,
  query,
  setQuery,
  page,
  setPage,
  onInspect,
}: {
  engagementId: string;
  claims: ReportData["scanner_claims"];
  query: string;
  setQuery: (q: string) => void;
  page: number;
  setPage: (n: number) => void;
  onInspect: (observationId: string) => void;
}) {
  const items = claims.filter((s) => `${s.title} ${s.target} ${s.source_tool}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <>
      <p className="text-[13px] text-ink-dim">
        These signals are not added to the conclusion count. Inspect the scanner evidence and any filed finding before judging
        impact or confidence.
      </p>
      <label className="flex items-center gap-2 rounded-lg border border-border bg-surface px-3 shadow-card focus-within:border-accent/60 focus-within:shadow-focus">
        <Search size={15} className="text-ink-faint" />
        <input
          aria-label="Search scanner signals"
          placeholder="Search signal, target or source…"
          className="w-full bg-transparent py-2.5 text-[13px] outline-none placeholder:text-ink-faint"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </label>
      <p className="-mt-2 text-[12px] text-ink-faint">{items.length} matching scanner signals</p>
      <div className="space-y-2.5">
        {items.slice(page * 30, (page + 1) * 30).map((s) => (
          <article key={s.observation_id} className="relative overflow-hidden rounded-xl border border-border bg-surface p-4 pl-5 shadow-card">
            <span className="absolute inset-y-0 left-0 w-1 bg-warn" />
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-warn/30 bg-warn/10 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-[0.04em] text-warn">
                Scanner claims {s.scanner_claimed_severity || "unspecified severity"}
              </span>
              <Chip>{s.source_tool}</Chip>
            </div>
            <h3 className="mt-2 text-[14px] font-semibold text-ink">{s.title}</h3>
            <p className="mt-0.5 break-all font-mono text-[12px] text-ink-dim">{s.target}</p>
            <div className="mt-3 flex gap-2">
              <button className="btn-outline text-[12.5px]" onClick={() => onInspect(s.observation_id)}>
                Inspect scanner evidence
              </button>
              <Link
                className="btn-outline text-[12.5px]"
                href={`/engagement/${encodeURIComponent(engagementId)}?tab=graph&asset=${encodeURIComponent(s.target)}`}
              >
                Explore target
              </Link>
            </div>
          </article>
        ))}
      </div>
      <Pager page={page} setPage={setPage} total={items.length} size={30} />
    </>
  );
}
