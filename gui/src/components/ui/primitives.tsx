import { cn } from "@/lib/cn";
import type { LucideIcon } from "lucide-react";

/** Semantic colour roles shared by stat cards, badges and icon chips. */
export type Tone = "accent" | "ok" | "warn" | "danger" | "critical" | "high" | "medium" | "low" | "info" | "neutral";

export const TONE: Record<Tone, { chip: string; text: string; bar: string; soft: string }> = {
  accent: { chip: "bg-accent/12 text-accent", text: "text-accent", bar: "bg-accent", soft: "bg-accent/10 text-accent-soft border-accent/25" },
  ok: { chip: "bg-ok/12 text-ok", text: "text-ok", bar: "bg-ok", soft: "bg-ok/10 text-ok border-ok/25" },
  warn: { chip: "bg-warn/14 text-warn", text: "text-warn", bar: "bg-warn", soft: "bg-warn/10 text-warn border-warn/30" },
  danger: { chip: "bg-danger/12 text-danger", text: "text-danger", bar: "bg-danger", soft: "bg-danger/10 text-danger border-danger/25" },
  critical: { chip: "bg-sev-critical/12 text-sev-critical", text: "text-sev-critical", bar: "bg-sev-critical", soft: "bg-sev-critical/10 text-sev-critical border-sev-critical/25" },
  high: { chip: "bg-sev-high/12 text-sev-high", text: "text-sev-high", bar: "bg-sev-high", soft: "bg-sev-high/10 text-sev-high border-sev-high/25" },
  medium: { chip: "bg-sev-medium/14 text-sev-medium", text: "text-sev-medium", bar: "bg-sev-medium", soft: "bg-sev-medium/10 text-sev-medium border-sev-medium/30" },
  low: { chip: "bg-sev-low/12 text-sev-low", text: "text-sev-low", bar: "bg-sev-low", soft: "bg-sev-low/10 text-sev-low border-sev-low/25" },
  info: { chip: "bg-sev-info/14 text-sev-info", text: "text-sev-info", bar: "bg-sev-info", soft: "bg-sev-info/10 text-sev-info border-sev-info/25" },
  neutral: { chip: "bg-ink/[0.06] text-ink-dim", text: "text-ink-dim", bar: "bg-ink-faint", soft: "bg-ink/[0.05] text-ink-dim border-border" },
};

/** A tinted square holding an icon — the app's standard icon treatment. */
export function IconChip({
  icon: Icon,
  tone = "accent",
  size = "md",
  className,
}: {
  icon: LucideIcon;
  tone?: Tone;
  size?: "sm" | "md" | "lg";
  className?: string;
}) {
  const box = size === "sm" ? "h-7 w-7 rounded-md" : size === "lg" ? "h-11 w-11 rounded-xl" : "h-9 w-9 rounded-lg";
  const px = size === "sm" ? 14 : size === "lg" ? 22 : 18;
  return (
    <span className={cn("grid flex-none place-items-center", box, TONE[tone].chip, className)}>
      <Icon size={px} />
    </span>
  );
}

/** Page scaffold — editorial header (eyebrow, large two-tone headline, lead)
 *  followed by a padded content column. */
export function Page({
  title,
  subtitle,
  description,
  actions,
  eyebrow,
  children,
  width = "max-w-[1180px]",
}: {
  title: string;
  /** Second headline line, set in a muted tone. */
  subtitle?: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  eyebrow?: string;
  children: React.ReactNode;
  width?: string;
}) {
  return (
    <div className="min-h-full">
      <div className={cn("mx-auto px-8 pb-12 pt-9", width)}>
        <div className="flex items-start gap-6">
          <div className="min-w-0 flex-1">
            {eyebrow && <p className="eyebrow mb-2 !text-accent">{eyebrow}</p>}
            <h1 className="text-[34px] font-bold leading-[1.08] tracking-[-0.035em] text-ink">
              {title}
              {subtitle && (
                <>
                  <br />
                  <span className="text-ink-faint">{subtitle}</span>
                </>
              )}
            </h1>
            {description && <p className="mt-3 max-w-2xl text-[15px] leading-relaxed text-ink-dim">{description}</p>}
          </div>
          {actions && <div className="flex flex-none items-center gap-2 pt-1">{actions}</div>}
        </div>
        <div className="mt-8 space-y-6">{children}</div>
      </div>
    </div>
  );
}

/** A titled surface. Header (title + optional icon/count/actions) sits above a hairline. */
export function Card({
  className,
  children,
  title,
  icon,
  count,
  actions,
  padded = true,
}: {
  className?: string;
  children: React.ReactNode;
  title?: string;
  icon?: LucideIcon;
  count?: number | string;
  actions?: React.ReactNode;
  padded?: boolean;
}) {
  return (
    <section className={cn("rounded-xl border border-border bg-surface shadow-card", className)}>
      {title && (
        <header className="flex items-center gap-2.5 border-b border-border px-4 py-3">
          {icon && <IconChip icon={icon} size="sm" tone="accent" />}
          <h2 className="text-[13.5px] font-semibold text-ink">{title}</h2>
          {count != null && (
            <span className="rounded-full bg-ink/[0.06] px-2 py-0.5 font-mono text-[11px] text-ink-dim">{count}</span>
          )}
          {actions && <div className="ml-auto flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={padded ? "p-4" : undefined}>{children}</div>
    </section>
  );
}

/** KPI card: tinted icon, small label, large figure, optional footnote. */
export function StatTile({
  label,
  value,
  sub,
  icon,
  tone = "accent",
  onClick,
  active,
}: {
  label: string;
  value: number | string;
  sub?: string;
  icon?: LucideIcon;
  tone?: Tone;
  onClick?: () => void;
  active?: boolean;
}) {
  const className = cn(
    "relative flex items-start gap-3.5 overflow-hidden rounded-2xl border bg-surface p-5 text-left shadow-card transition",
    onClick && "hover:-translate-y-px hover:shadow-lift",
    active ? "border-accent ring-1 ring-accent/40" : "border-border",
  );
  const inner = (
    <>
      {icon && <IconChip icon={icon} tone={tone} />}
      <div className="min-w-0">
        <div className="text-[12px] font-medium text-ink-dim">{label}</div>
        <div className="num mt-1 text-[30px] leading-none">
          {typeof value === "number" ? value.toLocaleString() : value}
        </div>
        {sub && <div className="mt-1.5 text-[12px] leading-snug text-ink-faint">{sub}</div>}
      </div>
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

/** Joined button group for filtering / switching views. */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  label,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode; count?: number }[];
  label?: string;
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className="inline-flex flex-wrap items-center gap-0.5 rounded-lg border border-border bg-surface-3/70 p-0.5"
    >
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            onClick={() => onChange(o.value)}
            aria-pressed={on}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[12.5px] font-medium transition-colors",
              on ? "bg-surface text-ink shadow-card" : "text-ink-dim hover:text-ink",
            )}
          >
            {o.label}
            {o.count != null && <span className="font-mono text-[11px] text-ink-faint">{o.count}</span>}
          </button>
        );
      })}
    </div>
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
