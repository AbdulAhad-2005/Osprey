"use client";

import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { MessageSquare, Radar, ShieldAlert, FileText, Copy, Check } from "lucide-react";
import { useWorkspace } from "@/components/shell/WorkspaceProvider";
import { ChatView } from "@/components/chat/ChatView";
import { AttackSurfaceTab } from "@/components/tabs/AttackSurfaceTab";
import { FindingsTab } from "@/components/tabs/FindingsTab";
import { ReportTab } from "@/components/tabs/ReportTab";
import { TabNav, type TabDef } from "@/components/ui/Tabs";
import { cn } from "@/lib/cn";

type TabKey = "chat" | "surface" | "findings" | "report";
const VALID: TabKey[] = ["chat", "surface", "findings", "report"];

export function EngagementWorkspace({ engagementId }: { engagementId: string }) {
  const { engagements } = useWorkspace();
  const router = useRouter();
  const search = useSearchParams();
  const engagement = engagements.find((e) => e.id === engagementId);
  const initialPrompt = search.get("intent") ?? undefined;

  const urlTab = (search.get("tab") as TabKey) ?? "chat";
  const [tab, setTab] = useState<TabKey>(VALID.includes(urlTab) ? urlTab : "chat");

  function changeTab(key: string) {
    const k = key as TabKey;
    setTab(k);
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
    { key: "findings", label: "Findings", icon: ShieldAlert, count: engagement?.findings_count },
    { key: "report", label: "Report", icon: FileText },
  ];

  return (
    <div className="flex h-full flex-col">
      {/* Workspace top bar */}
      <header className="flex items-center gap-4 border-b border-border px-4 py-2 pl-14">
        <TargetLabel target={engagement?.target ?? engagementId} id={engagementId} />
        {engagement && (
          <span className="hidden items-center gap-2 text-[12px] text-ink-faint md:flex">
            <span className="text-border-strong">·</span>
            {engagement.tools_executed} tools
          </span>
        )}
        <div className="ml-auto">
          <TabNav tabs={tabs} active={tab} onChange={changeTab} />
        </div>
      </header>

      {/* Body — chat stays mounted so a live run survives tab switches */}
      <div className="relative min-h-0 flex-1">
        <div className={cn("absolute inset-0", tab === "chat" ? "block" : "hidden")}>
          <ChatView engagementId={engagementId} initialPrompt={initialPrompt} />
        </div>
        {tab === "surface" && (
          <div className="absolute inset-0 overflow-y-auto">
            <AttackSurfaceTab engagementId={engagementId} />
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
      </div>
    </div>
  );
}

function TargetLabel({ target, id }: { target: string; id: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2">
      <span className="truncate font-mono text-[14px] font-medium text-ink">{target}</span>
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
        className="text-ink-faint transition-colors hover:text-ink-dim"
        title="Copy engagement id"
      >
        {copied ? <Check size={13} className="text-ok" /> : <Copy size={13} />}
      </button>
    </div>
  );
}
