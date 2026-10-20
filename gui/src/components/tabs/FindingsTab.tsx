"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronRight, ShieldCheck } from "lucide-react";
import { listFindings } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import { SEVERITY_ORDER } from "@/lib/surface";
import type { FindingSummary, Severity } from "@/lib/types";
import { SEVERITY_META } from "@/lib/format";
import { cn } from "@/lib/cn";
import { SeverityPill, ConfidenceDot } from "@/components/ui/SeverityPill";
import { Chip } from "@/components/ui/primitives";
import { Loading, EmptyState, ErrorState } from "@/components/ui/States";

export function FindingsTab({ engagementId }: { engagementId: string }) {
  const fnd = useResource((s) => listFindings(engagementId, s), [engagementId]);

  if (fnd.loading && !fnd.loaded) return <Loading label="Loading findings…" />;
  if (fnd.error) return <ErrorState message={fnd.error} onRetry={fnd.refetch} />;

  const findings = fnd.data ?? [];
  if (findings.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No findings yet"
        hint="As Osprey confirms vulnerabilities, exposed services, credentials and misconfigurations, they'll appear here grouped by severity."
      />
    );
  }

  const groups = SEVERITY_ORDER.map((sev) => ({
    sev,
    items: findings.filter((f) => (f.claim_severity ?? "none") === sev),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="mx-auto max-w-4xl space-y-6 px-5 py-5">
      {groups.map((g) => (
        <div key={g.sev}>
          <div className="mb-2 flex items-center gap-2">
            <span className={cn("h-2.5 w-2.5 rounded-full", SEVERITY_META[g.sev].dot)} />
            <h3 className={cn("text-[13px] font-semibold uppercase tracking-wide", SEVERITY_META[g.sev].text)}>
              {SEVERITY_META[g.sev].label}
            </h3>
            <span className="rounded-full bg-white/5 px-1.5 py-0.5 font-mono text-[11px] text-ink-dim">
              {g.items.length}
            </span>
          </div>
          <div className="space-y-1.5">
            {g.items.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function FindingCard({ finding }: { finding: FindingSummary }) {
  const [open, setOpen] = useState(false);
  const sev = (finding.claim_severity ?? "none") as Severity;
  const body = finding.description || finding.evidence_summary || finding.evidence || "";

  return (
    <div
      className={cn(
        "overflow-hidden rounded-xl border bg-surface/70 transition-colors hover:border-border-strong",
        sev === "critical" || sev === "high" ? SEVERITY_META[sev].border : "border-border",
      )}
    >
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-start gap-3 px-3.5 py-3 text-left">
        <SeverityPill severity={sev} size="sm" />
        <div className="min-w-0 flex-1">
          <div className="text-[14px] font-medium leading-snug text-ink">{finding.title}</div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-ink-faint">
            {finding.target && <span className="font-mono text-ink-dim">{finding.target}</span>}
            {finding.finding_type && <Chip className="text-ink-faint">{finding.finding_type.replace(/_/g, " ")}</Chip>}
            {finding.source_tool && <span>via {finding.source_tool}</span>}
            {finding.occurrence_count && finding.occurrence_count > 1 && <span>{finding.occurrence_count}× seen</span>}
          </div>
        </div>
        <div className="flex flex-none items-center gap-2.5">
          <ConfidenceDot confidence={finding.confidence} />
          <ChevronRight size={14} className={cn("text-ink-faint transition-transform", open && "rotate-90")} />
        </div>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="overflow-hidden border-t border-border"
          >
            <div className="space-y-3 px-3.5 py-3">
              {body ? (
                <p className="whitespace-pre-wrap text-[13px] leading-relaxed text-ink-dim">{body}</p>
              ) : (
                <p className="text-[12.5px] italic text-ink-faint">No description recorded.</p>
              )}
              {finding.tags && finding.tags.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {finding.tags.map((t) => (
                    <Chip key={t}>{t}</Chip>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
