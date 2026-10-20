"use client";

import { motion } from "framer-motion";
import { OspreyMark } from "@/components/brand/OspreyMark";

/**
 * Committed loading state for the engagement route. Rendered as the Suspense
 * fallback (and route `loading.tsx`) so a navigation always paints *this* route
 * instantly — never the stale previous page — while the workspace and its data
 * resolve. Mirrors the workspace chrome so the swap-in is seamless.
 */
export function WorkspaceSkeleton({ engagementId }: { engagementId?: string }) {
  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-4 border-b border-border px-4 py-2 pl-14">
        <div className="h-4 w-40 animate-pulse rounded bg-surface-3" />
        <div className="ml-auto hidden gap-2 md:flex">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-6 w-20 animate-pulse rounded-md bg-surface-2" />
          ))}
        </div>
      </header>
      <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-3">
        <motion.div
          animate={{ y: [0, -6, 0], rotate: [-2, 2, -2] }}
          transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut" }}
        >
          <OspreyMark size={44} />
        </motion.div>
        <p className="text-[13px] text-ink-faint">
          Opening engagement{engagementId ? ` · ${engagementId}` : ""}…
        </p>
      </div>
    </div>
  );
}
