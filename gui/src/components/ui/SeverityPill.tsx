import { cn } from "@/lib/cn";
import { SEVERITY_META } from "@/lib/format";
import type { Severity } from "@/lib/types";

export function SeverityPill({ severity, size = "md" }: { severity: Severity; size?: "sm" | "md" }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.none;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border font-medium",
        meta.bg,
        meta.text,
        meta.border,
        size === "sm" ? "px-1.5 py-0.5 text-[10.5px]" : "px-2 py-0.5 text-[11.5px]",
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", meta.dot)} />
      {meta.label}
    </span>
  );
}

export function ConfidenceDot({ confidence }: { confidence: string }) {
  const c = confidence.toLowerCase();
  const color =
    c === "confirmed"
      ? "bg-ok"
      : c === "likely" || c === "probable"
        ? "bg-amber"
        : c === "observed"
          ? "bg-signal"
          : "bg-ink-faint";
  return (
    <span className="inline-flex items-center gap-1.5 text-[11.5px] text-ink-dim" title={`confidence: ${confidence}`}>
      <span className={cn("h-1.5 w-1.5 rounded-full", color)} />
      {confidence}
    </span>
  );
}
