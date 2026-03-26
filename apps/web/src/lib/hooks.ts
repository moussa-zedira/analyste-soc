"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

// ---------------------------------------------------------------------------
// URL query-param helpers
// ---------------------------------------------------------------------------

export function readParam(
  sp: URLSearchParams,
  key: string,
  fallback: string,
): string {
  return sp.get(key) ?? fallback;
}

export function readInt(
  sp: URLSearchParams,
  key: string,
  fallback: number,
): number {
  const v = sp.get(key);
  if (v === null) return fallback;
  const n = parseInt(v, 10);
  return Number.isNaN(n) ? fallback : n;
}

/**
 * Returns a stable callback that merges a patch into the current URL search
 * params and navigates.  Empty/zero values are removed from the query string.
 */
export function usePushParams(basePath: string) {
  const router = useRouter();
  const searchParams = useSearchParams();

  return useCallback(
    (patch: Record<string, string | number | undefined>) => {
      const sp = new URLSearchParams(searchParams.toString());
      for (const [k, v] of Object.entries(patch)) {
        if (v === undefined || v === "" || v === 0) {
          sp.delete(k);
        } else {
          sp.set(k, String(v));
        }
      }
      router.push(`${basePath}?${sp.toString()}`);
    },
    [router, searchParams, basePath],
  );
}

// ---------------------------------------------------------------------------
// Generic data-fetching hook with cancellation
// ---------------------------------------------------------------------------

interface UseFetchResult<T> {
  data: T;
  loading: boolean;
  error: string | null;
}

/**
 * Fetches data via the provided async function every time `deps` change.
 * Automatically cancels stale requests and supports AbortSignal forwarding.
 */
export function useFetchData<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  initial: T,
  deps: readonly unknown[],
): UseFetchResult<T> {
  const [data, setData] = useState<T>(initial);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);

    fetcherRef
      .current(controller.signal)
      .then((res) => {
        if (!controller.signal.aborted) setData(res);
      })
      .catch((err) => {
        if (!controller.signal.aborted) {
          setError(err instanceof Error ? err.message : String(err));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, loading, error };
}

// ---------------------------------------------------------------------------
// Theme toggle hook
// ---------------------------------------------------------------------------

type Theme = "light" | "dark";

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(() => {
    if (typeof window === "undefined") return "dark";
    return (localStorage.getItem("theme") as Theme) ?? "dark";
  });

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    localStorage.setItem("theme", t);
    if (t === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(theme === "dark" ? "light" : "dark");
  }, [theme, setTheme]);

  useEffect(() => {
    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  }, [theme]);

  return { theme, toggleTheme };
}
