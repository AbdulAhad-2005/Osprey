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
}: {
  tabs: TabDef[];
  active: string;
  onChange: (key: string) => void;
  layoutId?: string;
}) {
  return (
    <div className="flex items-center gap-0.5">
      {tabs.map((t) => {
        const isActive = t.key === active;
        return (
          <button
            key={t.key}
            onClick={() => onChange(t.key)}
            className={cn(
              "relative flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[13px] font-medium transition-colors",
              isActive ? "text-ink" : "text-ink-dim hover:text-ink",
            )}
          >
            {t.icon && <t.icon size={14} className={isActive ? "text-amber" : undefined} />}
            {t.label}
            {t.count != null && t.count > 0 && (
              <span
                className={cn(
                  "rounded-full px-1.5 py-0.5 font-mono text-[10px]",
                  isActive ? "bg-amber/15 text-amber-soft" : "bg-white/5 text-ink-faint",
                )}
              >
                {t.count}
              </span>
            )}
            {isActive && (
              <motion.span
                layoutId={layoutId}
                className="absolute inset-x-1.5 -bottom-[7px] h-[2px] rounded-full bg-amber"
                transition={{ type: "spring", stiffness: 420, damping: 34 }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}
