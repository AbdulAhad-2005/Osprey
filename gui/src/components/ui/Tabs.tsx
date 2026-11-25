"use client";

import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/cn";

export interface TabDef {
  key: string;
  label: string;
  icon?: LucideIcon;
  count?: number;
}

export function TabNav({
  tabs,
  active,
  onChange,
  layoutId = "tab-underline",
  onHero = false,
}: {
  tabs: TabDef[];
  active: string;
  onChange: (key: string) => void;
  layoutId?: string;
  /** Render for the dark navy hero banner (light text). */
  onHero?: boolean;
}) {
  return (
    <div className="flex items-center gap-1" role="tablist">
      {tabs.map((t) => {
        const isActive = t.key === active;
        return (
          <button
            key={t.key}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(t.key)}
            className={cn(
              "relative flex flex-none items-center gap-1.5 whitespace-nowrap px-3 py-2.5 text-[13px] font-medium transition-colors",
              onHero
                ? isActive ? "text-white" : "text-white/60 hover:text-white"
                : isActive ? "text-ink" : "text-ink-dim hover:text-ink",
            )}
          >
            {t.icon && <t.icon size={14} className={isActive ? (onHero ? "text-[#8db7ff]" : "text-accent") : undefined} />}
            {t.label}
            {t.count != null && t.count > 0 && (
              <span
                className={cn(
                  "rounded-full px-1.5 py-0.5 font-mono text-[10px]",
                  isActive ? "bg-accent/15 text-accent-soft" : "bg-ink/[0.06] text-ink-faint",
                )}
              >
                {t.count}
              </span>
            )}
            {isActive && (
              <motion.span
                layoutId={layoutId}
                className={cn("absolute inset-x-2 bottom-0 h-[2px] rounded-t-full", onHero ? "bg-[#8db7ff]" : "bg-accent")}
                transition={{ type: "spring", stiffness: 420, damping: 34 }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}
