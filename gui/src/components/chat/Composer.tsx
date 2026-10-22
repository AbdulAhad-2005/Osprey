"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowUp, Pause, Play, Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";

export function Composer({
  onSend,
  onStop,
  onResume,
  resumable = false,
  submitting = false,
  streaming,
  disabled,
  placeholder = "Message Osprey — ask it to recon, probe, or report…",
}: {
  onSend: (text: string) => Promise<boolean>;
  onStop: () => void;
  onResume: () => void;
  resumable?: boolean;
  submitting?: boolean;
  streaming: boolean;
  disabled?: boolean;
  placeholder?: string;
}) {
  const [text, setText] = useState("");
  const ref = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = "0px";
    el.style.height = Math.min(el.scrollHeight, 200) + "px";
  }, [text]);

  async function submit() {
    const t = text.trim();
    if (!t || submitting || disabled) return;
    const draft = text;
    if (await onSend(t)) setText((current) => current === draft ? "" : current);
  }

  return (
    <div className="px-4 pb-4 pt-1">
      <div className="mx-auto max-w-3xl">
        <div
          className={cn(
            "panel flex items-end gap-2 px-3 py-2.5 shadow-lift transition-colors",
            !disabled && "focus-within:border-border-strong",
          )}
        >
          <textarea
            ref={ref}
            rows={1}
            value={text}
            disabled={disabled}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
                e.preventDefault();
                submit();
              }
            }}
            placeholder={disabled ? "Backend offline — start it to chat" : placeholder}
            className="max-h-[200px] w-full resize-none bg-transparent py-1 text-[14.5px] leading-relaxed text-ink placeholder:text-ink-faint focus:outline-none disabled:opacity-60"
          />
          {!text.trim() && streaming ? (
            <button
              onClick={onStop}
              className="grid h-9 w-9 flex-none place-items-center rounded-lg border border-border-strong text-ink-dim transition-colors hover:text-ink"
              disabled={submitting || disabled}
              title="Pause engagement"
              aria-label="Pause engagement"
            >
              {submitting ? <Loader2 size={14} className="animate-spin" /> : <Pause size={16} />}
            </button>
          ) : (
            <button
              onClick={() => text.trim() ? void submit() : onResume()}
              disabled={submitting || disabled || (!text.trim() && !resumable)}
              className="grid h-9 w-9 flex-none place-items-center rounded-lg bg-amber text-abyss transition-colors hover:bg-amber-soft disabled:bg-surface-3 disabled:text-ink-faint"
              title={text.trim() ? streaming ? "Send and redirect the current run" : "Send" : resumable ? "Resume engagement" : "Send"}
              aria-label={text.trim() ? "Send" : resumable ? "Resume engagement" : "Send"}
            >
              {submitting ? <Loader2 size={16} className="animate-spin" /> : !text.trim() && resumable ? <Play size={16} /> : <ArrowUp size={16} strokeWidth={2.5} />}
            </button>
          )}
        </div>
        <div className="mt-1.5 text-center text-[11px] text-ink-faint">
          {streaming ? "Pause to keep your progress, or send a message to redirect the run." : resumable ? "Resume from saved progress, or send a new instruction." : "Osprey can run live tools against your target. Review actions on authorized scope only."}
        </div>
      </div>
    </div>
  );
}
