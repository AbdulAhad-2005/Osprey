"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Eraser, FlaskConical, Copy, Check } from "lucide-react";
import type { Engagement } from "@/lib/types";
import { useChat } from "@/hooks/useChat";
import { useWorkspace } from "@/components/shell/WorkspaceProvider";
import { clearConversation } from "@/lib/api";
import { cn } from "@/lib/cn";
import { TurnView } from "./TurnView";
import { Composer } from "./Composer";
import { ActivityIndicator } from "./ActivityIndicator";

export function ChatView({
  engagementId,
  engagement,
  initialPrompt,
}: {
  engagementId: string;
  engagement?: Engagement;
  initialPrompt?: string;
}) {
  const { backendUp } = useWorkspace();
  const [mock, setMock] = useState(false);
  const chat = useChat(engagementId, { mock });
  const scrollRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const pinnedRef = useRef(true);
  const sentInitial = useRef(false);

  // Auto-send an initial instruction handed over from the launch screen.
  useEffect(() => {
    if (initialPrompt && !sentInitial.current && chat.turns.length === 0 && !chat.streaming) {
      sentInitial.current = true;
      chat.send(initialPrompt);
    }
  }, [initialPrompt, chat]);

  // Track whether the user is pinned to the bottom (so streaming doesn't yank
  // the view while they're scrolled up reading).
  function onScroll() {
    const el = scrollRef.current;
    if (!el) return;
    pinnedRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 120;
  }
  useLayoutEffect(() => {
    if (pinnedRef.current) bottomRef.current?.scrollIntoView({ block: "end" });
  });

  const showActivity =
    chat.streaming && chat.activity.kind !== "idle" && chat.activity.kind !== "error";

  return (
    <div className="flex h-full flex-col">
      {/* Top bar */}
      <header className="flex items-center gap-3 border-b border-border px-4 py-2.5 pl-14">
        <div className="min-w-0">
          <EngagementTitle engagement={engagement} fallback={engagementId} />
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          <button
            onClick={() => setMock((v) => !v)}
            className={cn(
              "flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[12px] transition-colors",
              mock
                ? "border-amber/50 bg-amber/10 text-amber-soft"
                : "border-border text-ink-faint hover:text-ink-dim",
            )}
            title="Demo mode: replay a scripted run without an LLM key"
          >
            <FlaskConical size={13} /> Demo
          </button>
          <button
            onClick={() => {
              chat.clear();
              if (!mock) void clearConversation(engagementId);
            }}
            className="btn-ghost"
            title="Clear conversation"
          >
            <Eraser size={15} />
          </button>
        </div>
      </header>

      {/* Stream */}
      <div ref={scrollRef} onScroll={onScroll} className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-3xl px-4 py-6">
          {chat.turns.length === 0 ? (
            <EmptyState mock={mock} />
          ) : (
            <div className="space-y-6">
              {chat.turns.map((t) => (
                <TurnView key={t.id} turn={t} onAnswer={chat.answer} />
              ))}
              {showActivity && (
                <div className="flex gap-3 pl-10">
                  <ActivityIndicator activity={chat.activity} />
                </div>
              )}
            </div>
          )}
          <div ref={bottomRef} />
        </div>
      </div>

      <Composer
        onSend={chat.send}
        onStop={chat.stop}
        streaming={chat.streaming}
        disabled={!mock && backendUp === false}
      />
    </div>
  );
}

function EngagementTitle({ engagement, fallback }: { engagement?: Engagement; fallback: string }) {
  const [copied, setCopied] = useState(false);
  const target = engagement?.target || fallback;
  return (
    <div className="flex items-center gap-2">
      <span className="truncate font-mono text-[14px] font-medium text-ink">{target}</span>
      <button
        onClick={() => {
          navigator.clipboard?.writeText(engagement?.id ?? fallback).then(
            () => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            },
            () => {},
          );
        }}
        className="text-ink-faint transition-colors hover:text-ink-dim"
        title="Copy engagement id"
      >
        {copied ? <Check size={13} className="text-ok" /> : <Copy size={13} />}
      </button>
      {engagement && (
        <span className="hidden items-center gap-2 text-[12px] text-ink-faint sm:flex">
          <span className="text-border-strong">·</span>
          {engagement.findings_count} findings
          <span className="text-border-strong">·</span>
          {engagement.tools_executed} tools
        </span>
      )}
    </div>
  );
}

function EmptyState({ mock }: { mock: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <p className="text-[15px] text-ink-dim">
        {mock
          ? "Demo mode — send anything to watch a scripted recon run."
          : "Engagement bound. Tell Osprey what to do."}
      </p>
      <p className="mt-1.5 text-[13px] text-ink-faint">
        e.g. “map the attack surface”, “find exposed services”, “what did we learn so far?”
      </p>
    </div>
  );
}
