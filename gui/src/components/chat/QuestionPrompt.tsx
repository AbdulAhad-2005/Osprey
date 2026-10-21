"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { CornerDownLeft, ShieldQuestion, CircleCheck } from "lucide-react";
import type { OperatorQuestion } from "@/lib/types";
import { cn } from "@/lib/cn";

export function QuestionPrompt({
  question,
  answered,
  onAnswer,
  inactive = false,
}: {
  question: OperatorQuestion;
  answered?: string;
  onAnswer: (value: string) => void;
  inactive?: boolean;
}) {
  const [freeform, setFreeform] = useState("");
  const isGate = question.kind === "gate";
  const resolved = answered != null;

  const chosen =
    resolved && question.options.find((o) => o.value === answered)?.label;

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        "rounded-xl border p-3.5",
        resolved
          ? "border-border bg-surface/50"
          : isGate
            ? "border-amber/40 bg-amber/[0.06] shadow-glow-amber"
            : "border-signal/35 bg-signal/[0.05]",
      )}
    >
      <div className="flex items-start gap-2.5">
        <span
          className={cn(
            "mt-0.5 grid h-6 w-6 flex-none place-items-center rounded-md",
            isGate ? "bg-amber/15 text-amber" : "bg-signal/15 text-signal",
          )}
        >
          <ShieldQuestion size={14} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="mb-0.5 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">
            {isGate ? "Decision required" : "Osprey needs your input"}
          </div>
          <p className="text-[14px] leading-relaxed text-ink">{question.text}</p>

          {resolved ? (
            <div className="mt-3 flex items-center gap-2 text-[13px] text-ink-dim">
              <CircleCheck size={15} className="text-ok" />
              You chose: <span className="font-medium text-ink">{chosen ?? answered}</span>
            </div>
          ) : inactive ? <p className="mt-3 text-xs text-ink-faint">This run has ended; the question is no longer open.</p> : (
            <>
              <div className="mt-3 grid gap-2">
                {question.options.map((o) => (
                  <button
                    key={o.value}
                    onClick={() => onAnswer(o.value)}
                    className={cn(
                      "group flex items-start gap-2.5 rounded-lg border px-3 py-2.5 text-left transition-colors",
                      o.intent === "danger"
                        ? "border-sev-critical/40 hover:border-sev-critical hover:bg-sev-critical/10"
                        : o.intent === "primary"
                          ? "border-amber/40 hover:border-amber hover:bg-amber/10"
                          : "border-border hover:border-border-strong hover:bg-white/[0.04]",
                    )}
                  >
                    <span
                      className={cn(
                        "mt-1 h-2 w-2 flex-none rounded-full",
                        o.intent === "danger"
                          ? "bg-sev-critical"
                          : o.intent === "primary"
                            ? "bg-amber"
                            : "bg-ink-faint group-hover:bg-ink-dim",
                      )}
                    />
                    <span className="min-w-0">
                      <span className="block text-[13.5px] font-medium text-ink">{o.label}</span>
                      {o.detail && (
                        <span className="mt-0.5 block text-[12px] leading-snug text-ink-dim">
                          {o.detail}
                        </span>
                      )}
                    </span>
                  </button>
                ))}
              </div>

              {question.allow_freeform && (
                <div className="mt-2 flex items-center gap-2 rounded-lg border border-border bg-base/50 px-3 py-1.5 focus-within:border-border-strong">
                  <input
                    value={freeform}
                    onChange={(e) => setFreeform(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && freeform.trim()) onAnswer(freeform.trim());
                    }}
                    placeholder="…or type a specific instruction"
                    className="w-full bg-transparent text-[13px] text-ink placeholder:text-ink-faint focus:outline-none"
                  />
                  <button
                    onClick={() => freeform.trim() && onAnswer(freeform.trim())}
                    disabled={!freeform.trim()}
                    className="btn-ghost p-1 disabled:opacity-30"
                    aria-label="Send answer"
                  >
                    <CornerDownLeft size={14} />
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </motion.div>
  );
}
