"use client";

import { useMemo, useState, type MouseEvent } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { PanelLeftClose, Search, Target, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { useWorkspace } from "./WorkspaceProvider";
import { cn } from "@/lib/cn";
import { deleteEngagement } from "@/lib/api";
import type { Engagement } from "@/lib/types";

export function Sidebar() {
  const { engagements, loading, error, toggleSidebar, refresh } = useWorkspace();
  const pathname = usePathname();
  const [q, setQ] = useState("");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return engagements;
    return engagements.filter(
      (e) =>
        e.target.toLowerCase().includes(needle) || (e.name ?? "").toLowerCase().includes(needle),
    );
  }, [engagements, q]);

  const activeId = pathname.startsWith("/engagement/")
    ? decodeURIComponent(pathname.split("/")[2] ?? "")
    : "";

  return (
    <aside className="flex h-full w-[264px] flex-none flex-col border-r border-border bg-surface-2/60 text-ink">
      <div className="flex h-14 flex-none items-center justify-between border-b border-border px-4">
        <div className="flex items-center gap-2">
          <h2 className="text-[14px] font-semibold tracking-[-0.01em]">Engagements</h2>
          <span className="rounded-full bg-ink/[0.06] px-2 py-0.5 font-mono text-[11px] text-ink-dim">{engagements.length}</span>
        </div>
        <div className="flex items-center gap-0.5">
          <button onClick={() => void refresh()} className="btn-ghost p-1.5" title="Refresh" aria-label="Refresh engagements">
            <RefreshCw size={14} className={cn(loading && "animate-spin")} />
          </button>
          <button onClick={toggleSidebar} className="btn-ghost p-1.5" title="Hide list" aria-label="Hide engagements">
            <PanelLeftClose size={16} />
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="px-3 py-3">
        <div className="flex items-center gap-2 rounded-lg border border-border bg-surface px-2.5 py-1.5 focus-within:border-accent/60 focus-within:shadow-focus">
          <Search size={14} className="text-ink-faint" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search engagements"
            className="w-full bg-transparent text-[13px] text-ink placeholder:text-ink-faint focus:outline-none"
          />
        </div>
      </div>

      {/* Engagement list */}
      <nav className="min-h-0 flex-1 overflow-y-auto px-2 pb-2">
        {loading && engagements.length === 0 ? (
          <div className="flex items-center gap-2 px-3 py-6 text-[13px] text-ink-faint">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : error ? (
          <div className="px-3 py-5 text-[12.5px] leading-relaxed text-ink-faint">
            Backend unreachable.
            <br />
            Start it, then{" "}
            <button onClick={() => void refresh()} className="text-accent-soft hover:underline">
              retry
            </button>
            .
          </div>
        ) : filtered.length === 0 ? (
          <div className="px-3 py-6 text-[12.5px] text-ink-faint">
            {q ? "No matches." : "No engagements yet. Start one from a target."}
          </div>
        ) : (
          <ul className="space-y-0.5">
            {filtered.map((e) => (
              <SidebarItem key={e.id} e={e} active={e.id === activeId} />
            ))}
          </ul>
        )}
      </nav>

    </aside>
  );
}

function SidebarItem({ e, active }: { e: Engagement; active: boolean }) {
  const { refresh } = useWorkspace();
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function onDelete(ev: MouseEvent) {
    ev.preventDefault();
    ev.stopPropagation();
    if (busy) return;
    const label = e.target || e.name || e.id;
    if (!window.confirm(`Delete engagement "${label}" and all its findings, observations and history?\n\nThis cannot be undone.`)) return;
    setBusy(true);
    try {
      await deleteEngagement(e.id);
      if (active) router.push("/");
      await refresh();
    } catch (err) {
      window.alert(`Could not delete: ${err instanceof Error ? err.message : "unknown error"}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <li>
      <div
        className={cn(
          "group relative flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] transition-colors",
          active ? "bg-accent/[0.09] text-ink shadow-[inset_2px_0_0_rgb(var(--c-accent))]" : "text-ink-dim hover:bg-ink/[0.06] hover:text-ink",
        )}
      >
        <Link href={`/engagement/${encodeURIComponent(e.id)}`} className="flex min-w-0 flex-1 items-center gap-2.5">
          <Target
            size={14}
            className={cn("flex-none", active ? "text-accent" : "text-ink-faint group-hover:text-ink-dim")}
          />
          <span className="min-w-0 flex-1 truncate font-medium">{e.target || e.name || e.id}</span>
        </Link>
        {e.findings_count > 0 && (
          <span title="Recorded rows, including legacy discovery facts" className="rounded-full bg-ink/[0.06] px-1.5 py-0.5 font-mono text-[10px] text-ink-dim group-hover:hidden">
            {e.findings_count}
          </span>
        )}
        <button
          onClick={onDelete}
          disabled={busy}
          className="hidden flex-none text-ink-faint transition-colors hover:text-danger group-hover:block"
          title="Delete engagement"
          aria-label="Delete engagement"
        >
          {busy ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
        </button>
      </div>
    </li>
  );
}
