"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface Resource<T> {
  data: T | undefined;
  loading: boolean;
  error: string | null;
  /** True after at least one load settled (for distinguishing first-load from refetch). */
  loaded: boolean;
  refetch: () => void;
}

/**
 * Minimal data-fetch hook: one consistent loading/error/refetch contract every
 * screen reuses instead of re-hand-rolling `useEffect + fetch + 3 states`. Not
 * a cache — screens that need sharing/revalidation can graduate to a cache
 * later without changing call sites, because the returned shape stays the same.
 *
 * `deps` controls refetch (same semantics as a useEffect dep array). The
 * fetcher receives an AbortSignal; stale responses are dropped.
 */
export function useResource<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: ReadonlyArray<unknown>,
): Resource<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    const ctrl = new AbortController();
    let active = true;
    setLoading(true);
    setError(null);
    fetcherRef
      .current(ctrl.signal)
      .then((result) => {
        if (!active) return;
        setData(result);
        setError(null);
      })
      .catch((e: unknown) => {
        if (!active || ctrl.signal.aborted) return;
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
        setLoaded(true);
      });
    return () => {
      active = false;
      ctrl.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const refetch = useCallback(() => setNonce((n) => n + 1), []);
  return { data, loading, error, loaded, refetch };
}
