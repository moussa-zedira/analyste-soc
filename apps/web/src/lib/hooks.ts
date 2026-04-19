"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

// ---------------------------------------------------------------------------
// URL query-param helpers
// ---------------------------------------------------------------------------

/** Lit un parametre de requete URL avec une valeur par defaut. */
export function readParam(
  sp: URLSearchParams,
  key: string,
  fallback: string,
): string {
  return sp.get(key) ?? fallback;
}

/** Lit un parametre de requete URL en tant qu'entier avec une valeur par defaut. */
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

/** Hook de gestion du theme clair/sombre avec persistance dans localStorage. */
export function useTheme() {
  // IMPORTANT : on initialise toujours a "dark" pour que le premier render
  // (SSR et CSR) soit identique, puis on lit le localStorage cote client
  // dans un useEffect afin d'eviter un hydration mismatch.
  const [theme, setThemeState] = useState<Theme>("dark");

  useEffect(() => {
    try {
      const saved = localStorage.getItem("theme") as Theme | null;
      if (saved === "light" || saved === "dark") {
        setThemeState(saved);
      }
    } catch {
      /* storage indisponible (Safari private, etc.) : on reste sur dark */
    }
  }, []);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    try {
      localStorage.setItem("theme", t);
    } catch {
      /* ignore */
    }
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
