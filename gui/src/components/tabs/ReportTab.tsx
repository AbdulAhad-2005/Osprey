"use client";

import { useEffect, useState } from "react";
import { Download, Printer, FileText, ShieldAlert, Radar, ListChecks, ScrollText, Sun, Moon, RefreshCw } from "lucide-react";
import { getReport, reportMarkdownUrl } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import type { ReportData, ReportFinding, Severity } from "@/lib/types";
import { SEVERITY_META } from "@/lib/format";
import { cn } from "@/lib/cn";
import { SeverityPill } from "@/components/ui/SeverityPill";
import { Chip } from "@/components/ui/primitives";
import { Loading, EmptyState, ErrorState } from "@/components/ui/States";
import { RecordInspector } from "@/components/ui/RecordInspector";

export function ReportTab({ engagementId }: { engagementId: string }) {
  const rep = useResource((s) => getReport(engagementId, s), [engagementId]);
  const [light, setLight] = useState(true);
  const [exportError, setExportError] = useState("");
  useEffect(() => {
    let previouslyClosed: HTMLDetailsElement[] = [];
    const before = () => {
      previouslyClosed = [...document.querySelectorAll<HTMLDetailsElement>("#osprey-report details:not([open])")];
      previouslyClosed.forEach((element) => { element.open = true; });
    };
    const after = () => previouslyClosed.forEach((element) => { element.open = false; });
    window.addEventListener("beforeprint", before);
    window.addEventListener("afterprint", after);
    return () => { window.removeEventListener("beforeprint", before); window.removeEventListener("afterprint", after); };
  }, []);

  // Remember the report theme per viewer (print-friendly light vs. on-screen dark).
  useEffect(() => {
    try {
      setLight(localStorage.getItem("osprey.report.light") !== "0");
    } catch {
      /* ignore */
    }
  }, []);
  function toggleTheme() {
    setLight((v) => {
      const next = !v;
      try {
        localStorage.setItem("osprey.report.light", next ? "1" : "0");
      } catch {
        /* ignore */
      }
      return next;
    });
  }

  if (rep.loading && !rep.loaded) return <Loading label="Assembling report…" />;
  if (rep.error) return <ErrorState message={rep.error} onRetry={rep.refetch} />;
  const report = rep.data;
  if (!report || report.error) {
    return <EmptyState icon={FileText} title="Report unavailable" hint={report?.error ?? "No engagement data."} />;
  }

  async function downloadMarkdown() {
    const res = await fetch(reportMarkdownUrl(engagementId));
    if (!res.ok) throw new Error("Report export failed. Please refresh and retry.");
    const text = await res.text();
    const blob = new Blob([text], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `osprey-report-${report!.meta.target || engagementId}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div className="relative">
      {/* Export toolbar (not printed) */}
      <div className="no-print sticky top-0 z-10 flex items-center justify-end gap-2 border-b border-border bg-base/80 px-5 py-2 backdrop-blur">
        <button onClick={rep.refetch} className="btn-ghost" disabled={rep.loading}><RefreshCw size={14}/> Refresh</button>
        <button
          onClick={toggleTheme}
          className="btn-ghost"
          title={light ? "Switch to dark report" : "Switch to light (print-friendly) report"}
        >
          {light ? <Moon size={14} /> : <Sun size={14} />}
          {light ? "Dark" : "Light"}
        </button>
        {exportError && <span role="alert" className="text-xs text-red-soft">{exportError}</span>}
        <button onClick={() => { setExportError(""); void downloadMarkdown().catch((error) => setExportError(error.message)); }} className="btn-outline">
          <Download size={14} /> Markdown
        </button>
        <button onClick={() => window.print()} className="btn-primary">
          <Printer size={14} /> Print / PDF
        </button>
      </div>

      <article
        id="osprey-report"
        className={cn("mx-auto max-w-4xl px-6 py-8", light && "report-light")}
      >
        <ReportHeader report={report} />
        <ExecutiveSummary report={report} />
        <section><H2 icon={ListChecks}>Assessment limitations</H2><ul className="list-disc space-y-2 pl-5 text-[13px] leading-relaxed text-ink-dim">{report.limitations?.map((line) => <li key={line}>{line}</li>)}</ul></section>
        <ScopeSection report={report} />
        <MethodologySection report={report} />
        <FindingsSection report={report} />
        {!!report.review_candidates?.length && <details className="report-appendix mt-6 rounded-xl border border-border p-4"><summary className="cursor-pointer text-sm font-semibold text-ink">Legacy records requiring review · {report.review_candidates.length}</summary><p className="my-3 text-sm text-ink-dim">These older records have a severity label but were stored as structural facts or execution notes. They are excluded from security-conclusion totals. Full original evidence is available in Findings → Legacy records to review.</p><ul className="space-y-2 text-xs text-ink-dim">{report.review_candidates.map((finding) => <li key={finding.id} className="break-words"><span className="font-mono">{finding.id}</span> · {finding.title} · {finding.target} · recorded severity: {finding.severity}</li>)}</ul></details>}
        <section><H2 icon={ListChecks}>Remediation priorities</H2>{report.remediation_plan?.map((group) => <div key={group.priority} className="mb-4"><h3 className="text-sm font-semibold text-ink">{group.priority.toUpperCase()} · {group.finding_ids.length} findings</h3><ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-ink-dim">{group.actions.map((action) => <li key={action}>{action}</li>)}</ul></div>)}</section>
        {report.scanner_claims.length > 0 && <ScannerClaimsSection report={report} />}
        <AppendixSection report={report} />
        <footer className="mt-10 border-t border-border pt-4 text-center text-[11.5px] text-ink-faint">
          Generated by Osprey · {report.meta.generated_at.slice(0, 19).replace("T", " ")} UTC
        </footer>
      </article>
    </div>
  );
}

function H2({ icon: Icon, children }: { icon: typeof Radar; children: React.ReactNode }) {
  return (
    <h2 className="mb-3 mt-9 flex items-center gap-2 border-b border-border pb-1.5 text-[16px] font-semibold text-ink">
      <Icon size={16} className="text-amber" />
      {children}
    </h2>
  );
}

function ReportHeader({ report }: { report: ReportData }) {
  const risk = report.executive_summary.overall_risk;
  const meta = SEVERITY_META[risk] ?? SEVERITY_META.none;
  return (
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <div className="text-[11px] font-medium uppercase tracking-[0.18em] text-ink-faint">
          Penetration Test Report
        </div>
        <h1 className="mt-1 font-serif text-[30px] font-semibold leading-tight text-ink">
          {report.meta.target}
        </h1>
        <div className="mt-1.5 text-[12.5px] text-ink-faint">
          Engagement <span className="font-mono text-ink-dim">{report.meta.engagement_id}</span> · status{" "}
          {report.meta.status} · {report.meta.tools_executed} tool runs
        </div>
      </div>
      <div className={cn("rounded-xl border px-4 py-3 text-center", meta.border, meta.bg)}>
        <div className="text-[10px] font-medium uppercase tracking-wider text-ink-faint">Highest technical severity</div>
        <div className={cn("mt-0.5 text-[22px] font-bold", meta.text)}>{report.executive_summary.overall_risk_label}</div>
      </div>
    </header>
  );
}

const STAT_LABELS: [string, string][] = [
  ["subdomains", "Subdomains"],
  ["hosts", "Hosts"],
  ["services", "Services"],
  ["technologies", "Technologies"],
  ["identities", "OSINT"],
  ["secrets", "Secrets"],
  ["findings", "Findings"],
];

function ExecutiveSummary({ report }: { report: ReportData }) {
  const es = report.executive_summary;
  return (
    <section>
      <H2 icon={ScrollText}>Executive Summary</H2>
      <p className="text-[14px] leading-relaxed text-ink-dim">{es.narrative}</p>
      <div className="mt-5 grid gap-2 sm:grid-cols-5" aria-label="Security findings by severity">
        {(["critical", "high", "medium", "low", "info"] as Severity[]).map((severity) => <div key={severity} className="rounded-lg border border-border p-3"><div className="flex items-center justify-between"><SeverityPill severity={severity} /><span className="font-mono text-lg text-ink">{report.totals.by_severity[severity] || 0}</span></div><div className="mt-3 h-1.5 rounded bg-surface-2"><div className={cn("h-full rounded", SEVERITY_META[severity].dot)} style={{width: `${100 * (report.totals.by_severity[severity] || 0) / Math.max(1, report.totals.findings)}%`}} /></div></div>)}
      </div>
      <div className="mt-4 grid grid-cols-3 gap-2 sm:grid-cols-7">
        {STAT_LABELS.map(([key, label]) => (
          <div key={key} className="rounded-lg border border-border bg-surface/60 px-2.5 py-2 text-center">
            <div className="font-mono text-[18px] font-semibold text-ink">{es.key_stats[key] ?? 0}</div>
            <div className="text-[10px] uppercase tracking-wide text-ink-faint">{label}</div>
          </div>
        ))}
      </div>
      {es.top_risks.length > 0 && (
        <div className="mt-4">
          <div className="mb-1.5 text-[12px] font-semibold text-ink">Top risks</div>
          <ul className="space-y-1">
            {es.top_risks.map((r, i) => (
              <li key={i} className="flex items-center gap-2 text-[13px] text-ink-dim">
                <SeverityPill severity={r.severity as Severity} size="sm" />
                {r.title}
                <span className="font-mono text-[11.5px] text-ink-faint">{r.target}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 py-1 text-[13px]">
      <div className="w-44 flex-none text-ink-faint">{label}</div>
      <div className="text-ink-dim">{value}</div>
    </div>
  );
}

function ScopeSection({ report }: { report: ReportData }) {
  const s = report.scope;
  const yn = (b: boolean) => (b ? "Yes" : "No");
  return (
    <section>
      <H2 icon={ListChecks}>Scope &amp; Rules of Engagement</H2>
      <div className="rounded-xl border border-border bg-surface/50 px-4 py-2">
        <Row label="In scope" value={s.in_scope.join(", ") || "—"} />
        <Row label="Out of scope" value={s.out_of_scope.join(", ") || "—"} />
        <Row label="Exploitation allowed" value={<span className={s.allow_exploitation ? "text-sev-high" : "text-ok"}>{yn(s.allow_exploitation)}</span>} />
        <Row label="Destructive actions" value={<span className={s.destructive_actions_allowed ? "text-sev-high" : "text-ok"}>{yn(s.destructive_actions_allowed)}</span>} />
        <Row label="Rate limit" value={`${s.rate_limit_rps} req/s · ${s.max_concurrent_tools} concurrent`} />
        {s.time_window && <Row label="Time window" value={s.time_window} />}
      </div>
    </section>
  );
}

function MethodologySection({ report }: { report: ReportData }) {
  return (
    <section>
      <H2 icon={Radar}>Methodology</H2>
      {report.methodology.length === 0 ? (
        <p className="text-[13px] italic text-ink-faint">No tool activity recorded.</p>
      ) : (
        <div className="space-y-2.5">
          {report.methodology.map((ph) => (
            <div key={ph.phase}>
              <div className="text-[13px] font-medium text-ink">{ph.phase}</div>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {ph.tools.map((t) => (
                  <Chip key={t}>{t}</Chip>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function FindingsSection({ report }: { report: ReportData }) {
  return (
    <section>
      <H2 icon={ShieldAlert}>Findings</H2>
      {report.findings_by_severity.length === 0 ? (
        <p className="text-[13px] italic text-ink-faint">No confirmed findings were concluded.</p>
      ) : (
        <div className="space-y-5">
          {report.findings_by_severity.map((g) => (
            <div key={g.severity}>
              <div className="mb-2 flex items-center gap-2">
                <span className={cn("h-2.5 w-2.5 rounded-full", SEVERITY_META[g.severity].dot)} />
                <span className={cn("text-[13px] font-semibold uppercase tracking-wide", SEVERITY_META[g.severity].text)}>
                  {SEVERITY_META[g.severity].label}
                </span>
                <span className="font-mono text-[11px] text-ink-faint">{g.count}</span>
              </div>
              <div className="space-y-3">
                {g.findings.map((f) => (
                  <FindingBlock key={f.id} f={f} engagementId={report.meta.engagement_id} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export function FindingBlock({ f, engagementId }: { f: ReportFinding; engagementId?: string }) {
  const [inspect, setInspect] = useState(false);
  return (
    <div id={`finding-${f.id}`} className={cn("break-inside-avoid rounded-xl border bg-surface/50 p-4", SEVERITY_META[f.severity].border)}>
      <div className="flex items-start gap-2.5">
        <SeverityPill severity={f.severity} size="sm" />
        <div className="text-[14.5px] font-semibold text-ink">{f.title}</div>
        <span className="ml-auto font-mono text-[10px] text-ink-faint">{f.id}</span>
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-ink-faint">
        <span className="font-mono text-ink-dim">{f.target || "—"}</span>
        {f.type && <Chip>{f.type.replace(/_/g, " ")}</Chip>}
        {f.source_tool && <span>via {f.source_tool}</span>}
        <span>confidence: {f.confidence}</span>
      </div>
      {f.description && <p className="mt-2.5 whitespace-pre-wrap text-[13px] leading-relaxed text-ink-dim">{f.description}</p>}
      {f.evidence_snippet && (
        <div className="mt-2.5">
          <div className="mb-1 text-[10px] font-medium uppercase tracking-wider text-ink-faint">Evidence</div>
          <pre className="report-evidence max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-border bg-abyss p-2.5 font-mono text-[11.5px] leading-relaxed text-ink-dim">
            {f.evidence_snippet}
          </pre>
        </div>
      )}
      {!!f.observation_ids?.length && <p className="mt-2 break-all font-mono text-[10px] text-ink-faint">Observation references: {f.observation_ids.join(", ")}</p>}
      {engagementId && <button className="btn-outline no-print mt-3 text-xs" onClick={()=>setInspect(true)}>Inspect original record &amp; observations</button>}
      <div className={cn("mt-2.5 rounded-lg border px-3 py-2 text-[12.5px] text-ink-dim",f.remediation_recorded ? "border-ok/25 bg-ok/[0.06]" : "border-amber/25 bg-amber/[0.06]")}>
        <span className={cn("font-semibold", f.remediation_recorded ? "text-ok" : "text-amber")}>{f.remediation_recorded ? "Recorded remediation. " : "Remediation needs authoring. "}</span>
        {f.remediation_hint}
      </div>
      {inspect && engagementId && <RecordInspector engagementId={engagementId} records={[{kind:"finding",id:f.id},...(f.observation_ids || []).map(id=>({kind:"observation" as const,id}))]} title={f.title} onClose={()=>setInspect(false)}/>}
    </div>
  );
}

function ScannerClaimsSection({ report }: { report: ReportData }) {
  return (
    <section>
      <H2 icon={ShieldAlert}>Unverified Scanner Claims</H2>
      <p className="mb-2 text-[12.5px] italic text-ink-faint">
        Raw scanner matches, not confirmed findings — each requires verification before it becomes a conclusion.
      </p>
      <div className="space-y-1">
        {report.scanner_claims.map((c) => (
          <div key={c.observation_id} className="flex items-center gap-2 text-[12.5px] text-ink-dim">
            <Chip>{c.source_tool}</Chip>
            {c.title}
            <span className="font-mono text-[11px] text-ink-faint">{c.target}</span>
            <span className="ml-auto text-[11px] text-ink-faint">claimed: {c.scanner_claimed_severity}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function AppendixSection({ report }: { report: ReportData }) {
  return (
    <section>
      <H2 icon={FileText}>Appendix — Attack Surface Inventory</H2>
      <div className="space-y-5">
        {report.recon_appendix.map((sec) => (
          <details key={sec.key} className="report-appendix break-inside-avoid rounded-lg border border-border p-3">
            <summary className="cursor-pointer text-sm font-semibold text-ink">{sec.label} · {sec.count.toLocaleString()} assets</summary>
            <div className="mb-1.5 text-[13px] font-semibold text-ink">
              {sec.label} <span className="font-mono text-[11px] text-ink-faint">{sec.count}</span>
            </div>
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full border-collapse text-[12.5px]">
                <tbody>
                  {sec.items.map((it, i) => (
                    <tr key={i} className="border-b border-border/60 last:border-0">
                      <td className="w-[45%] break-all px-3 py-1.5 font-mono text-ink">{it.value}</td>
                      <td className="px-3 py-1.5 text-ink-dim">{it.detail || "—"}</td>
                      <td className="px-3 py-1.5 text-right text-ink-faint">{it.source_tool}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        ))}
      </div>
    </section>
  );
}
