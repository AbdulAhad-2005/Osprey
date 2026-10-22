"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { useRouter, useSearchParams } from "next/navigation";
import { Eraser, FlaskConical, Zap } from "lucide-react";
import { useChat } from "@/hooks/useChat";
import { useWorkspace } from "@/components/shell/WorkspaceProvider";
import { QUICK_INTENTS, kickoffPrompt } from "@/lib/intents";
import { OspreyMark } from "@/components/brand/OspreyMark";
import { cn } from "@/lib/cn";
import { TurnView } from "./TurnView";
import { Composer } from "./Composer";
import { ActivityIndicator } from "./ActivityIndicator";
import { BackgroundJobs } from "./BackgroundJobs";

export function ChatView({
  engagementId,
  initialPrompt,
  visible = true,
}: {
  engagementId: string;
  initialPrompt?: string;
  visible?: boolean;
}) {
  const { backendUp, engagements } = useWorkspace();
  const [mock, setMock] = useState(false);
  const chat = useChat(engagementId, { mock });
  const target = engagements.find((e) => e.id === engagementId)?.target;
  const scrollRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const pinnedRef = useRef(true);
  const sentInitial = useRef(false);
  const router = useRouter();
  const search = useSearchParams();

  useEffect(() => {
    if (initialPrompt && !sentInitial.current && !chat.loading && !chat.streaming) {
      sentInitial.current = true;
      const params = new URLSearchParams(search.toString());
      params.delete("intent");
      router.replace(`/engagement/${encodeURIComponent(engagementId)}${params.size ? `?${params}` : ""}`, {scroll:false});
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
            if (window.confirm("Clear this engagement's saved chat and stop its current run? Findings and evidence are retained.")) void chat.clear();
          }}
          className="rounded-lg border border-border bg-surface/70 p-1.5 text-ink-faint transition-colors hover:text-ink-dim"
          title="Clear conversation"
        >
          <Eraser size={15} />
        </button>
      </div>

      <div ref={scrollRef} onScroll={onScroll} className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-3xl px-4 py-6">
          {!mock && <BackgroundJobs engagementId={engagementId} visible={visible}/>}
          {chat.loading && <p className="py-8 text-sm text-ink-faint">Restoring conversation…</p>}
          {chat.error && <p role="alert" className="my-3 rounded-lg border border-sev-high/30 p-3 text-sm text-sev-high">{chat.error}</p>}
          {chat.activity.kind === "error" && <p role="alert" className="my-3 rounded-lg border border-sev-high/30 p-3 text-sm text-sev-high">{chat.activity.message}</p>}
          {chat.turns.length === 0 ? (
            <ChatLanding
              mock={mock}
              target={target}
              disabled={chat.loading || chat.submitting || chat.streaming || (!mock && backendUp === false)}
              onSend={chat.send}
            />
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
              {chat.run.resumable && <p role="status" className="rounded-lg border border-amber/25 bg-amber/5 px-3 py-2 text-sm text-ink-dim">
                {chat.run.reason === "turn_limit" ? "The previous run reached its step limit." : chat.run.reason === "empty_response" ? "The model ended the previous run without a response." : chat.run.state === "completed" ? "This turn finished. The engagement is still open." : chat.run.state === "paused" ? "Engagement paused." : "The previous run was interrupted."}
                {" "}Your conversation and recorded evidence are saved. Resume below to continue.
              </p>}
            </div>
          )}
          <div ref={bottomRef} />
        </div>
      </div>

      <Composer
        onSend={chat.send}
        onStop={chat.stop}
        onResume={() => { void chat.send("Continue this existing engagement from its saved progress. Review recent tool results and outstanding work, preserve the original objective and scope, and avoid repeating completed actions without a reason."); }}
        resumable={chat.run.resumable}
        submitting={chat.submitting}
        streaming={chat.streaming}
        disabled={chat.loading || (!mock && backendUp === false)}
      />
    </div>
  );
}

function ChatLanding({
  mock,
  target,
  disabled,
  onSend,
}: {
  mock: boolean;
  target?: string;
  disabled: boolean;
  onSend: (prompt: string) => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="flex flex-col items-center py-16 text-center"
    >
      <motion.div
        animate={{ y: [0, -5, 0] }}
        transition={{ duration: 4.5, repeat: Infinity, ease: "easeInOut" }}
        className="mb-4"
      >
        <OspreyMark size={52} />
      </motion.div>
      <h2 className="font-serif text-[22px] font-semibold tracking-tight text-ink">
        {mock ? "Demo mode" : target ? "Engagement bound" : "Ready"}
      </h2>
      <p className="mt-1.5 max-w-md text-[13.5px] text-ink-dim">
        {mock
          ? "Send anything to watch a scripted recon run — no model key needed."
          : target
            ? <>Osprey is pointed at <span className="font-mono text-ink">{target}</span>. Start the hunt, or tell it exactly what to do.</>
            : "Tell Osprey what to do, or start autonomous recon."}
      </p>

      {/* Primary one-click start — no prompt required */}
      <button
        onClick={() => onSend(kickoffPrompt(target))}
        disabled={disabled}
        className="btn-primary mt-6 gap-2 disabled:opacity-50"
      >
        <Zap size={15} /> Start autonomous recon
      </button>
      <p className="mt-2 text-[11.5px] text-ink-faint">
        Recon first · widens the surface · pauses before anything intrusive
      </p>

      {/* Suggestion chips */}
      <div className="mt-7 w-full max-w-xl">
        <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-ink-faint">
          Or start from a goal
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {QUICK_INTENTS.map((q) => (
            <button
              key={q.label}
              onClick={() => onSend(q.prompt)}
              disabled={disabled}
              className="group flex items-start gap-2.5 rounded-xl border border-border bg-surface/50 px-3.5 py-3 text-left transition-colors hover:border-border-strong hover:bg-surface-2 disabled:opacity-50"
            >
              <span className="mt-0.5 grid h-6 w-6 flex-none place-items-center rounded-md bg-amber/12 text-amber transition-colors group-hover:bg-amber/20">
                <q.icon size={13.5} />
              </span>
              <span className="min-w-0">
                <span className="block text-[13px] font-medium text-ink">{q.label}</span>
                <span className="mt-0.5 block text-[11.5px] leading-snug text-ink-faint">{q.prompt}</span>
              </span>
            </button>
          ))}
        </div>
      </div>
    </motion.div>
  );
}
