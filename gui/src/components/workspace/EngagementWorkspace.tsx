"use client";

import { useState, useEffect } from "react";
import dynamic from "next/dynamic";
import { useRouter, useSearchParams } from "next/navigation";
import { MessageSquare, Radar, Share2, ShieldAlert, FileText, Copy, Check, Database, ChevronRight } from "lucide-react";
import Link from "next/link";
import { useWorkspace } from "@/components/shell/WorkspaceProvider";
import { ChatView } from "@/components/chat/ChatView";
import { EvidenceTab } from "@/components/tabs/EvidenceTab";
import { AttackSurfaceTab } from "@/components/tabs/AttackSurfaceTab";
import { FindingsTab } from "@/components/tabs/FindingsTab";
import { ReportTab } from "@/components/tabs/ReportTab";
import { TabNav, type TabDef } from "@/components/ui/Tabs";
import { WorkspaceSkeleton } from "./WorkspaceSkeleton";
import { getEngagement } from "@/lib/api";
import type { Engagement } from "@/lib/types";
import { cn } from "@/lib/cn";

type TabKey = "chat" | "surface" | "graph" | "findings" | "evidence" | "report";
const VALID: TabKey[] = ["chat", "surface", "graph", "findings", "evidence", "report"];
// Keep the graph/layout engine out of the initial chat bundle.
const GraphTab = dynamic(() => import("@/components/tabs/GraphTab").then((module) => module.GraphTab), {
  loading: () => <p className="p-6 text-sm text-ink-faint">Loading relationship map…</p>,
});

export function EngagementWorkspace({ engagementId }: { engagementId: string }) {
  const { engagements, loading } = useWorkspace();
  const router = useRouter();
  const search = useSearchParams();

  const [directEngagement, setDirectEngagement] = useState<Engagement | null>(null);
  const [checkingDirect, setCheckingDirect] = useState(false);
  const [notFound, setNotFound] = useState(false);

  const engagement = engagements.find((e) => e.id === engagementId) ?? directEngagement;
  const initialPrompt = search.get("intent") ?? undefined;

  useEffect(() => {
    if (engagements.some((e) => e.id === engagementId)) {
      setNotFound(false);
      return;
    }
    if (loading) return;

    let cancelled = false;
    setCheckingDirect(true);
    getEngagement(engagementId)
      .then((eng) => {
        if (!cancelled) {
          setDirectEngagement(eng);
          setNotFound(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setNotFound(true);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setCheckingDirect(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [engagementId, engagements, loading]);

  const urlTab = (search.get("tab") as TabKey) ?? "chat";
  const tab: TabKey = VALID.includes(urlTab) ? urlTab : "chat";

  function changeTab(key: string) {
    const k = key as TabKey;
    const params = new URLSearchParams(search.toString());
    if (k === "chat") params.delete("tab");
    else params.set("tab", k);
    params.delete("intent"); // don't re-fire the initial prompt on tab change
    const qs = params.toString();
    router.replace(`/engagement/${encodeURIComponent(engagementId)}${qs ? "?" + qs : ""}`, {
      scroll: false,
    });
  }

  const tabs: TabDef[] = [
    { key: "chat", label: "Chat", icon: MessageSquare },
    { key: "surface", label: "Attack Surface", icon: Radar },
    { key: "graph", label: "Graph", icon: Share2 },
    { key: "findings", label: "Findings", icon: ShieldAlert },
    { key: "evidence", label: "Evidence", icon: Database },
    { key: "report", label: "Report", icon: FileText },
  ];

  if (notFound) {
    const fallback = engagements[0];
    return (
      <div className="flex h-full flex-col items-center justify-center p-6 text-center">
        <div className="mx-auto max-w-md">
          <div className="mb-4 inline-flex h-14 w-14 items-center justify-center rounded-2xl border border-danger/30 bg-danger/10 text-danger shadow-sm">
            <ShieldAlert size={28} />
          </div>
          <h2 className="font-serif text-2xl font-semibold tracking-tight text-ink">
            Engagement Not Found
          </h2>
          <p className="mt-2 text-sm text-ink-dim leading-relaxed">
            The engagement <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-ink">{engagementId}</code> does not exist in the active database. It may have been deleted, or the database was recreated.
          </p>

          <div className="mt-6 flex flex-col sm:flex-row items-center justify-center gap-3">
            <button
              onClick={() => router.push("/")}
              className="btn-primary w-full sm:w-auto px-4 py-2"
            >
              Start New Engagement
            </button>
            {fallback && (
              <button
                onClick={() => router.push(`/engagement/${encodeURIComponent(fallback.id)}`)}
                className="btn-outline w-full sm:w-auto px-4 py-2"
              >
                Go to {fallback.target || fallback.id}
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  if ((loading || checkingDirect) && !engagement) {
    return <WorkspaceSkeleton engagementId={engagementId} />;
  }

  return (
    <div className="flex h-full flex-col">
      {/* Workspace hero */}
      <header className="hero-bg relative flex-none overflow-hidden text-white">
        <img
          src="/osprey-mark.svg"
          alt=""
          aria-hidden
          className="pointer-events-none absolute -right-6 -top-6 w-[320px] select-none opacity-[0.13] [filter:brightness(3)_saturate(0)]"
        />
        <div className="relative px-8 pt-5">
          <div className="flex items-center gap-1.5 text-[12.5px] text-[#a9bde8]">
            <Link href="/" className="hover:text-white">Engagements</Link>
            <ChevronRight size={12} className="opacity-60" />
            <span className="truncate">{engagement?.name || engagementId}</span>
          </div>
          <div className="mt-2 flex items-end justify-between gap-6">
            <div className="min-w-0">
              <div className="flex items-center gap-3">
                <h1 className="truncate text-[28px] font-bold leading-tight tracking-[-0.03em]">
                  {engagement?.target ?? engagementId}
                </h1>
                {engagement && <StatusBadge status={engagement.status} />}
              </div>
              <CopyId id={engagementId} />
            </div>
            {engagement && (
              <dl className="hidden flex-none items-center gap-7 pb-1 md:flex">
                <HeaderStat label="Findings" value={engagement.findings_count} />
                <HeaderStat label="Tools run" value={engagement.tools_executed} />
              </dl>
            )}
          </div>
        </div>
        <div className="relative mt-3 overflow-x-auto px-6">
          <TabNav tabs={tabs} active={tab} onChange={changeTab} onHero />
        </div>
      </header>

      {/* Body — chat stays mounted so a live run survives tab switches */}
      <div className="relative min-h-0 flex-1">
        <div className={cn("absolute inset-0", tab === "chat" ? "block" : "hidden")}>
          <ChatView key={engagementId} engagementId={engagementId} initialPrompt={initialPrompt} visible={tab === "chat"} />
        </div>
        {tab === "surface" && (
          <div className="absolute inset-0 overflow-y-auto">
            <AttackSurfaceTab engagementId={engagementId} />
          </div>
        )}
        {tab === "graph" && (
          <div className="absolute inset-0">
            <GraphTab key={engagementId} engagementId={engagementId} />
          </div>
        )}
        {tab === "findings" && (
          <div className="absolute inset-0 overflow-y-auto">
            <FindingsTab engagementId={engagementId} />
          </div>
        )}
        {tab === "report" && (
          <div className="absolute inset-0 overflow-y-auto">
            <ReportTab engagementId={engagementId} />
          </div>
        )}
        {tab === "evidence" && <div className="absolute inset-0 overflow-y-auto"><EvidenceTab engagementId={engagementId}/></div>}
      </div>
    </div>
  );
}

function HeaderStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="text-right">
      <dd className="text-[22px] font-semibold leading-none tabular-nums tracking-[-0.02em]">{value.toLocaleString()}</dd>
      <dt className="mt-1 text-[10.5px] font-semibold uppercase tracking-[0.1em] text-[#8fa6d8]">{label}</dt>
    </div>
  );
}

const STATUS_DOT: Record<string, string> = { active: "bg-[#34d399]", running: "bg-[#34d399]", paused: "bg-[#fbbf24]", completed: "bg-[#8db7ff]", failed: "bg-[#f87171]" };

function StatusBadge({ status }: { status: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-white/20 bg-white/10 px-2.5 py-0.5 text-[11.5px] font-semibold capitalize">
      <span className={cn("h-1.5 w-1.5 rounded-full", STATUS_DOT[status.toLowerCase()] ?? "bg-white/60")} />
      {status}
    </span>
  );
}

function CopyId({ id }: { id: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() =>
        navigator.clipboard?.writeText(id).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          },
          () => {},
        )
      }
      className="mt-1 inline-flex items-center gap-1.5 font-mono text-[12px] text-[#9db3e3] transition-colors hover:text-white"
      title="Copy engagement id"
    >
      {id}
      {copied ? <Check size={11} className="text-[#34d399]" /> : <Copy size={11} />}
    </button>
  );
}
