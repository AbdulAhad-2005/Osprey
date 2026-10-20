"use client";

import { AnimatePresence, motion } from "framer-motion";
import { PanelLeft } from "lucide-react";
import { Sidebar } from "./Sidebar";
import { useWorkspace } from "./WorkspaceProvider";

export function AppShell({ children }: { children: React.ReactNode }) {
  const { sidebarCollapsed, toggleSidebar } = useWorkspace();

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-base text-ink">
      <AnimatePresence initial={false}>
        {!sidebarCollapsed && (
          <motion.div
            key="sidebar"
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 264, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            className="h-full flex-none overflow-hidden"
          >
            <Sidebar />
          </motion.div>
        )}
      </AnimatePresence>

      <main className="relative flex min-w-0 flex-1 flex-col">
        {/* Floating reopen control when the sidebar is hidden */}
        <AnimatePresence>
          {sidebarCollapsed && (
            <motion.button
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -6 }}
              onClick={toggleSidebar}
              className="glass absolute left-3 top-3 z-20 rounded-lg p-2 text-ink-dim hover:text-ink"
              title="Show sidebar"
              aria-label="Show sidebar"
            >
              <PanelLeft size={17} />
            </motion.button>
          )}
        </AnimatePresence>
        {children}
      </main>
    </div>
  );
}
