"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Eraser, FlaskConical } from "lucide-react";
import { useChat } from "@/hooks/useChat";
import { useWorkspace } from "@/components/shell/WorkspaceProvider";
import { clearConversation } from "@/lib/api";
import { cn } from "@/lib/cn";
import { TurnView } from "./TurnView";
import { Composer } from "./Composer";
import { ActivityIndicator } from "./ActivityIndicator";

export function ChatView({
  engagementId,
  initialPrompt,
}: {
  engagementId: string;
  initialPrompt?: string;
}) {
  const { backendUp } = useWorkspace();
  const [mock, setMock] = useState(false);
  const chat = useChat(engagementId, { mock });
  const scrollRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const pinnedRef = useRef(true);
  const sentInitial = useRef(false);

  useEffect(() => {
    if (initialPrompt && !sentInitial.current && chat.turns.length === 0 && !chat.streaming) {
      sentInitial.current = true;
      chat.send(initialPrompt);
    }
  }, [initialPrompt, chat]);

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
    <div className="relative flex h-full flex-col">
      {/* Unobtrusive chat controls */}
      <div className="absolute right-3 top-2.5 z-10 flex items-center gap-1.5">
        <button
          onClick={() => setMock((v) => !v)}
          className={cn(
            "flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[12px] transition-colors",
            mock
              ? "border-amber/50 bg-amber/10 text-amber-soft"
              : "border-border bg-surface/70 text-ink-faint hover:text-ink-dim",
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
          className="rounded-lg border border-border bg-surface/70 p-1.5 text-ink-faint transition-colors hover:text-ink-dim"
          title="Clear conversation"
        >
          <Eraser size={15} />
        </button>
      </div>

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
