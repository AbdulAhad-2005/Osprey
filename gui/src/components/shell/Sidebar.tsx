"use client";

import { useMemo, useState, type MouseEvent } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { PanelLeftClose, Plus, Search, Target, Loader2, RefreshCw, Settings, Trash2 } from "lucide-react";
import { OspreyLogo } from "@/components/brand/OspreyLogo";
import { useWorkspace } from "./WorkspaceProvider";
import { cn } from "@/lib/cn";
import { deleteEngagement } from "@/lib/api";
import type { Engagement } from "@/lib/types";

export function Sidebar() {
  const { engagements, loading, error, backendUp, toggleSidebar, refresh } = useWorkspace();
  const pathname = usePathname();
  const router = useRouter();
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
    <aside className="flex h-full w-[264px] flex-none flex-col border-r border-border bg-surface/60">
      {/* Brand + hide */}
      <div className="flex items-center justify-between px-3.5 pt-4 pb-3">
        <Link href="/" className="transition-opacity hover:opacity-90">
          <OspreyLogo markSize={26} size="md" />
        </Link>
        <button
          onClick={toggleSidebar}
          className="btn-ghost -mr-1"
          title="Hide sidebar"
          aria-label="Hide sidebar"
        >
          <PanelLeftClose size={17} />
        </button>
      </div>

      {/* New engagement */}
      <div className="px-3 pb-2">
        <button
          onClick={() => router.push("/")}
          className="group flex w-full items-center gap-2.5 rounded-lg border border-border bg-surface-2 px-3 py-2.5 text-sm text-ink transition-colors hover:border-amber/50 hover:bg-surface-3"
        >
          <span className="grid h-5 w-5 place-items-center rounded-md bg-amber/15 text-amber transition-colors group-hover:bg-amber/25">
            <Plus size={14} strokeWidth={2.5} />
          </span>
          New engagement
          {/* <kbd className="ml-auto rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-ink-faint">
            ⌘N
          </kbd> */}
        </button>
      </div>

      {/* Search */}
      <div className="px-3 pb-2">
        <div className="flex items-center gap-2 rounded-lg border border-border bg-base/60 px-2.5 py-1.5 focus-within:border-border-strong">
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
      <div className="mt-1 flex items-center justify-between px-4 pb-1">
        <span className="text-[11px] font-medium uppercase tracking-wider text-ink-faint">
          Engagements
        </span>
        <button onClick={() => void refresh()} className="btn-ghost p-1" title="Refresh">
          <RefreshCw size={12} className={cn(loading && "animate-spin")} />
        </button>
      </div>
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
            <button onClick={() => void refresh()} className="text-amber-soft hover:underline">
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

      {/* Footer: backend status + settings */}
      <div className="flex items-center gap-2 border-t border-border px-4 py-2.5 text-[12px] text-ink-dim">
        <span
          className={cn(
            "h-1.5 w-1.5 rounded-full",
            backendUp == null ? "bg-ink-faint" : backendUp ? "bg-ok animate-pulse-ring" : "bg-danger",
          )}
        />
        {backendUp == null ? "Connecting…" : backendUp ? "Backend live" : "Backend offline"}
        <Link href="/settings" className="btn-ghost ml-auto -mr-1 p-1" title="Settings" aria-label="Settings">
          <Settings size={15} />
        </Link>
      </div>
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
          active ? "bg-surface-3 text-ink" : "text-ink-dim hover:bg-white/[0.04] hover:text-ink",
        )}
      >
        <Link href={`/engagement/${encodeURIComponent(e.id)}`} className="flex min-w-0 flex-1 items-center gap-2.5">
          <Target
            size={14}
            className={cn("flex-none", active ? "text-amber" : "text-ink-faint group-hover:text-ink-dim")}
          />
          <span className="min-w-0 flex-1 truncate font-medium">{e.target || e.name || e.id}</span>
        </Link>
        {e.findings_count > 0 && (
          <span title="Recorded rows, including legacy discovery facts" className="rounded-full bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-ink-dim group-hover:hidden">
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
