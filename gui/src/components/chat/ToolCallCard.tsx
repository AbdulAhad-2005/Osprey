"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  ChevronRight,
  Radar,
  Network,
  Globe,
  ShieldAlert,
  Crosshair,
  Satellite,
  KeyRound,
  Database,
  Terminal,
  Users,
  Check,
  X,
  Loader2,
  type LucideIcon,
} from "lucide-react";
import type { ToolCallView } from "@/lib/types";
import { toolCategory, toolLabel, workerTag, formatDuration, type ToolCategory } from "@/lib/format";
import { cn } from "@/lib/cn";
import { outputFailed, toolOutput } from "@/lib/toolOutput";

const CAT_META: Record<ToolCategory, { icon: LucideIcon; color: string; ring: string }> = {
  recon: { icon: Radar, color: "text-signal", ring: "bg-signal/12" },
  network: { icon: Network, color: "text-signal-soft", ring: "bg-signal/12" },
  web: { icon: Globe, color: "text-amber-soft", ring: "bg-amber/12" },
  vuln: { icon: ShieldAlert, color: "text-sev-high", ring: "bg-sev-high/12" },
  exploit: { icon: Crosshair, color: "text-sev-critical", ring: "bg-sev-critical/12" },
  osint: { icon: Satellite, color: "text-[#a78bfa]", ring: "bg-[#a78bfa]/12" },
  creds: { icon: KeyRound, color: "text-amber", ring: "bg-amber/12" },
  memory: { icon: Database, color: "text-ink-dim", ring: "bg-white/5" },
  shell: { icon: Terminal, color: "text-ink-dim", ring: "bg-white/5" },
  agent: { icon: Users, color: "text-ok", ring: "bg-ok/12" },
};

export function ToolCallCard({ call }: { call: ToolCallView }) {
  const [open, setOpen] = useState(false);
  const cat = toolCategory(call.name);
  const meta = CAT_META[cat];
  const Icon = meta.icon;
  const worker = workerTag(call.name);
  const prettyArgs = formatArgs(call.args);
  const status = call.status === "ok" && outputFailed(call.result) ? "fail" : call.status;

  return (
    <div
      className={cn(
        "overflow-hidden rounded-lg border bg-surface/70 transition-colors",
        status === "fail" ? "border-sev-critical/35" : "border-border hover:border-border-strong",
      )}
    >
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2.5 px-2.5 py-2 text-left"
      >
        <span className={cn("grid h-6 w-6 flex-none place-items-center rounded-md", meta.ring)}>
          <Icon size={13.5} className={meta.color} />
        </span>

        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate font-mono text-[12.5px] font-medium text-ink">
            {toolLabel(call.name)}
          </span>
          {worker && (
            <span className="rounded bg-ok/12 px-1 py-0.5 font-mono text-[9.5px] text-ok">
              {worker}
            </span>
          )}
          {call.source && call.source !== "tool" && (
            <span className="rounded bg-white/5 px-1 py-0.5 font-mono text-[9.5px] text-ink-faint">
              {call.source}
            </span>
          )}
        </span>

        <span className="ml-auto flex flex-none items-center gap-2.5 text-[11px] text-ink-faint">
          {call.findingTitles && call.findingTitles.length > 0 && (
            <span className="rounded-full bg-amber/12 px-1.5 py-0.5 font-medium text-amber-soft">
              {call.findingTitles.length} finding{call.findingTitles.length > 1 ? "s" : ""}
            </span>
          )}
          {call.status !== "running" && call.durationSeconds != null && (
            <span className="font-mono tabular-nums">{formatDuration(call.durationSeconds)}</span>
          )}
          <StatusIcon status={status} />
          <ChevronRight
            size={13}
            className={cn("transition-transform", open && "rotate-90")}
          />
        </span>
      </button>
      {prettyArgs && <div className="truncate px-11 pb-2 font-mono text-[11px] text-ink-faint" title={prettyArgs}>{prettyArgs.replace(/\s+/g, " ")}</div>}

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
            className="overflow-hidden border-t border-border"
          >
            {prettyArgs && (
              <div className="border-b border-border bg-base/40 px-3 py-2">
                <div className="mb-1 text-[10px] font-medium uppercase tracking-wider text-ink-faint">
                  Arguments
                </div>
                <pre className="overflow-x-auto font-mono text-[11.5px] leading-relaxed text-ink-dim">
                  {prettyArgs}
                </pre>
              </div>
            )}
            <div className="px-3 py-2">
              <div className="mb-1 text-[10px] font-medium uppercase tracking-wider text-ink-faint">
                Output
              </div>
              {call.status === "running" ? (
                <div className="flex items-center gap-2 py-1 font-mono text-[12px] text-ink-faint">
                  <Loader2 size={12} className="animate-spin" /> running…
                </div>
              ) : (
                <ToolOutput result={call.result || ""} name={call.name} />
              )}
              {call.findingTitles && call.findingTitles.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {call.findingTitles.map((f, i) => (
                    <span
                      key={i}
                      className="rounded-md border border-amber/25 bg-amber/10 px-2 py-0.5 font-mono text-[11px] text-amber-soft"
                    >
                      {f}
                    </span>
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

function OutputText({text}: {text: string}) {
  const [limit, setLimit] = useState(16000);
  return <>
    <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words font-mono text-[11.5px] leading-relaxed text-ink-dim">{text.slice(0, limit) || "(no output)"}</pre>
    {text.length > limit && <button className="mt-2 text-xs text-amber" onClick={() => setLimit((n) => n + 16000)}>Show more · {Math.min(limit, text.length).toLocaleString()} / {text.length.toLocaleString()} characters</button>}
  </>;
}

function ToolOutput({result, name}: {result: string; name: string}) {
  const parsed = toolOutput(result);
  function download() {
    const url = URL.createObjectURL(new Blob([result], {type: "text/plain;charset=utf-8"}));
    const link = document.createElement("a");
    link.href = url;
    link.download = `${name.replace(/[^a-z0-9_-]/gi, "_")}-output.txt`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <div className="space-y-3">
    {parsed.summary && <p className="break-words text-xs text-ink">{parsed.summary.slice(0, 1000)}{parsed.summary.length > 1000 ? "…" : ""}</p>}
    {parsed.error && <p className="break-words text-xs text-sev-high">{parsed.error}</p>}
    {parsed.sections.length ? parsed.sections.map((section) => section.label === "Diagnostics" ?
      <details key={section.label}><summary className="cursor-pointer text-xs text-ink-faint">Diagnostics · stderr</summary><OutputText text={section.content}/></details> :
      <OutputText key={section.label} text={section.content}/>) : <OutputText text={result}/>}
    {parsed.guidance && <details><summary className="cursor-pointer text-xs text-ink-faint">Tool guidance</summary><p className="whitespace-pre-wrap break-words pt-2 text-xs text-ink-dim">{parsed.guidance}</p></details>}
    <div className="flex items-start gap-3 border-t border-border pt-2">
      {parsed.sections.length > 0 && <details className="min-w-0 flex-1"><summary className="cursor-pointer text-xs text-ink-faint">Complete recorded result · command, metadata and evidence references</summary><OutputText text={result}/></details>}
      <button onClick={download} className="flex-none text-xs text-amber">Download output</button>
    </div>
  </div>;
}

function StatusIcon({ status }: { status: ToolCallView["status"] }) {
  if (status === "running")
    return <Loader2 aria-label="Running" size={13} className="animate-spin text-signal" />;
  if (status === "ok") return <Check aria-label="Completed" size={13} className="text-ok" />;
  if (status === "stopped") return <span className="text-ink-faint">interrupted</span>;
  return <X aria-label="Failed" size={13} className="text-sev-critical" />;
}

function formatArgs(args?: string): string | null {
  if (!args) return null;
  const trimmed = args.trim();
  if (!trimmed || trimmed === "{}") return null;
  try {
    const obj = JSON.parse(trimmed);
    if (obj && typeof obj === "object" && Object.keys(obj).length === 0) return null;
    return JSON.stringify(obj, null, 2);
  } catch {
    return trimmed;
  }
}
