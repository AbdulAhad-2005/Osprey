import { cn } from "@/lib/cn";

export interface DonutSegment {
  key: string;
  label: string;
  value: number;
  /** Tailwind background class for the legend dot (e.g. `bg-sev-high`). */
  dot: string;
  /** CSS colour for the arc (use rgb(var(--c-…))). */
  color: string;
}

/** Ring chart with a centred total and an optional clickable legend. */
export function Donut({
  segments,
  size = 176,
  thickness = 20,
  centerLabel = "findings",
  active,
  onSelect,
}: {
  segments: DonutSegment[];
  size?: number;
  thickness?: number;
  centerLabel?: string;
  active?: string;
  onSelect?: (key: string) => void;
}) {
  const total = segments.reduce((n, s) => n + s.value, 0);
  const r = (size - thickness) / 2;
  const circumference = 2 * Math.PI * r;
  const gap = segments.filter((s) => s.value > 0).length > 1 ? 3 : 0;
  let offset = 0;

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} role="img" aria-label={`${total} ${centerLabel}`}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgb(var(--c-surface-3))" strokeWidth={thickness} />
          {segments.map((s) => {
            if (!s.value || !total) return null;
            const len = (circumference * s.value) / total;
            const el = (
              <circle
                key={s.key}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={s.color}
                strokeWidth={active === s.key ? thickness + 4 : thickness}
                strokeDasharray={`${Math.max(len - gap, 0.5)} ${circumference - len + gap}`}
                strokeDashoffset={-offset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
                className="transition-[stroke-width] duration-150"
              />
            );
            offset += len;
            return el;
          })}
        </svg>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="num text-[32px] leading-none">{total.toLocaleString()}</div>
            <div className="mt-1 text-[11.5px] text-ink-faint">{centerLabel}</div>
          </div>
        </div>
      </div>
      <ul className="mt-5 w-full space-y-1">
        {segments.map((s) => (
          <li key={s.key}>
            <button
              onClick={() => onSelect?.(s.key)}
              disabled={!onSelect}
              className={cn(
                "flex w-full items-center gap-2.5 rounded-md px-2 py-1 text-[13px] text-ink-dim transition-colors",
                onSelect && "hover:bg-ink/[0.05] hover:text-ink",
                active === s.key && "bg-ink/[0.06] text-ink",
              )}
            >
              <span className={cn("h-2 w-2 rounded-full", s.dot)} />
              {s.label}
              <span className="ml-auto font-semibold tabular-nums text-ink">{s.value.toLocaleString()}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
