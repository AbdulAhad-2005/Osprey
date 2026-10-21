"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { Engagement } from "@/lib/types";
import { getHealth, listEngagements } from "@/lib/api";

interface WorkspaceState {
  engagements: Engagement[];
  loading: boolean;
  error: string | null;
  backendUp: boolean | null;
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (v: boolean) => void;
  refresh: () => Promise<void>;
}

const Ctx = createContext<WorkspaceState | null>(null);

const SIDEBAR_KEY = "osprey.sidebar.collapsed";

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);
  const [sidebarCollapsed, setCollapsedState] = useState(false);

  useEffect(() => {
    try {
      const v = localStorage.getItem(SIDEBAR_KEY);
      if (v === "1") setCollapsedState(true);
    } catch {
      /* private mode / blocked storage — ignore */
    }
  }, []);

  const setSidebarCollapsed = useCallback((v: boolean) => {
    setCollapsedState(v);
    try {
      localStorage.setItem(SIDEBAR_KEY, v ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, []);

  const toggleSidebar = useCallback(
    () => setSidebarCollapsed(!sidebarCollapsed),
    [sidebarCollapsed, setSidebarCollapsed],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [list, health] = await Promise.allSettled([listEngagements(), getHealth()]);
      if (list.status === "fulfilled") {
        setEngagements(
          list.value.slice().sort((a, b) => (b.updated_at ?? "").localeCompare(a.updated_at ?? "")),
        );
      } else {
        setError(String(list.reason?.message ?? list.reason ?? "failed to load engagements"));
      }
      setBackendUp(health.status === "fulfilled" ? !!health.value.ready : false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    let disposed = false;
    const check = async () => {
      if (document.visibilityState === "hidden") return;
      try { const health = await getHealth(); if (!disposed) setBackendUp(!!health.ready); }
      catch { if (!disposed) setBackendUp(false); }
    };
    const timer = window.setInterval(() => void check(), 15000);
    window.addEventListener("focus", check);
    return () => { disposed = true; window.clearInterval(timer); window.removeEventListener("focus", check); };
  }, []);

  const value = useMemo<WorkspaceState>(
    () => ({
      engagements,
      loading,
      error,
      backendUp,
      sidebarCollapsed,
      toggleSidebar,
      setSidebarCollapsed,
      refresh,
    }),
    [engagements, loading, error, backendUp, sidebarCollapsed, toggleSidebar, setSidebarCollapsed, refresh],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useWorkspace(): WorkspaceState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useWorkspace must be used within WorkspaceProvider");
  return ctx;
}
