import { Loader2, Inbox, TriangleAlert, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/cn";

export function Loading({ label = "Loading…", className }: { label?: string; className?: string }) {
  return (
    <div className={cn("flex items-center justify-center gap-2 py-16 text-[13px] text-ink-faint", className)}>
      <Loader2 size={15} className="animate-spin" />
      {label}
    </div>
  );
}

export function EmptyState({
  title,
  hint,
  icon: Icon = Inbox,
  className,
}: {
  title: string;
  hint?: string;
  icon?: LucideIcon;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-2 py-16 text-center", className)}>
      <span className="grid h-10 w-10 place-items-center rounded-xl border border-border bg-surface-2 text-ink-faint">
        <Icon size={18} />
      </span>
      <div className="text-[14px] text-ink-dim">{title}</div>
      {hint && <div className="max-w-sm text-[12.5px] text-ink-faint">{hint}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
      <span className="grid h-10 w-10 place-items-center rounded-xl border border-danger/30 bg-danger/10 text-danger">
        <TriangleAlert size={18} />
      </span>
      <div className="max-w-md text-[13px] text-ink-dim">{message}</div>
      {onRetry && (
        <button onClick={onRetry} className="btn-outline">
          Retry
        </button>
      )}
    </div>
  );
}
