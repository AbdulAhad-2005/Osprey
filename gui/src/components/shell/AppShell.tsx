"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Rail } from "./Rail";
import { Sidebar } from "./Sidebar";
import { useWorkspace } from "./WorkspaceProvider";

export function AppShell({ children }: { children: React.ReactNode }) {
  const { sidebarCollapsed } = useWorkspace();

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-base text-ink">
      <Rail />
      <AnimatePresence initial={false}>
        {!sidebarCollapsed && (
          <motion.div
            key="flyout"
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 264, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
            className="h-full flex-none overflow-hidden"
          >
            <Sidebar />
          </motion.div>
        )}
      </AnimatePresence>

      <main className="relative flex min-w-0 flex-1 flex-col">{children}</main>
    </div>
  );
}
