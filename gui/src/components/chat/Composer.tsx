"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowUp, Square } from "lucide-react";
import { cn } from "@/lib/cn";

export function Composer({
  onSend,
  onStop,
  streaming,
  disabled,
  placeholder = "Message Osprey — ask it to recon, probe, or report…",
}: {
  onSend: (text: string) => void;
  onStop: () => void;
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

  function submit() {
    const t = text.trim();
    if (!t || streaming || disabled) return;
    onSend(t);
    setText("");
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
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                submit();
              }
            }}
            placeholder={disabled ? "Backend offline — start it to chat" : placeholder}
            className="max-h-[200px] w-full resize-none bg-transparent py-1 text-[14.5px] leading-relaxed text-ink placeholder:text-ink-faint focus:outline-none disabled:opacity-60"
          />
          {streaming ? (
            <button
              onClick={onStop}
              className="grid h-9 w-9 flex-none place-items-center rounded-lg border border-border-strong text-ink-dim transition-colors hover:text-ink"
              title="Stop"
              aria-label="Stop"
            >
              <Square size={14} className="fill-current" />
            </button>
          ) : (
            <button
              onClick={submit}
              disabled={!text.trim() || disabled}
              className="grid h-9 w-9 flex-none place-items-center rounded-lg bg-amber text-abyss transition-colors hover:bg-amber-soft disabled:bg-surface-3 disabled:text-ink-faint"
              title="Send"
              aria-label="Send"
            >
              <ArrowUp size={16} strokeWidth={2.5} />
            </button>
          )}
        </div>
        <div className="mt-1.5 text-center text-[11px] text-ink-faint">
          Osprey can run live tools against your target. Review actions on authorized scope only.
        </div>
      </div>
    </div>
  );
}
