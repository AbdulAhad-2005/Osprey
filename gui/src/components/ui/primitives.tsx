import { cn } from "@/lib/cn";
import type { LucideIcon } from "lucide-react";

export function Card({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("rounded-xl border border-border bg-surface shadow-card", className)}>
      {children}
    </div>
  );
}

export function SectionHeader({
  title,
  count,
  icon: Icon,
  accent,
  right,
}: {
  title: string;
  count?: number;
  icon?: LucideIcon;
  accent?: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="mb-2.5 flex items-center gap-2">
      {Icon && <Icon size={15} className={accent ?? "text-ink-dim"} />}
      <h3 className="text-[13px] font-semibold tracking-wide text-ink">{title}</h3>
      {count != null && (
        <span className="rounded-full bg-white/5 px-1.5 py-0.5 font-mono text-[11px] text-ink-dim">
          {count}
        </span>
      )}
      {right && <div className="ml-auto">{right}</div>}
    </div>
  );
}

export function StatTile({
  label,
  value,
  sub,
  icon: Icon,
  accent = "text-ink",
  onClick,
  active,
}: {
  label: string;
  value: number | string;
  sub?: string;
  icon?: LucideIcon;
  accent?: string;
  onClick?: () => void;
  active?: boolean;
}) {
  const className = cn(
    "flex flex-col gap-1 rounded-xl border bg-surface/70 px-3.5 py-3 text-left transition-colors",
    onClick && "hover:border-border-strong",
    active ? "border-amber/50 bg-amber/[0.06]" : "border-border",
  );
  const inner = (
    <>
      <div className="flex items-center gap-1.5">
        {Icon && <Icon size={13} className={cn(accent, "opacity-80")} />}
        <span className="text-[11px] font-medium uppercase tracking-wider text-ink-faint">{label}</span>
      </div>
      <div className={cn("font-mono text-[22px] font-semibold tabular-nums leading-none", accent)}>{value}</div>
      {sub && <div className="text-[11.5px] text-ink-faint">{sub}</div>}
    </>
  );
  return onClick ? (
    <button onClick={onClick} className={className}>
      {inner}
    </button>
  ) : (
    <div className={className}>{inner}</div>
  );
}

export function Chip({
  children,
  className,
  title,
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-dim",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function CopyableMono({ value, className }: { value: string; className?: string }) {
  return (
    <span
      className={cn("font-mono text-[12.5px] text-ink", className)}
      title={value}
    >
      {value}
    </span>
  );
}
