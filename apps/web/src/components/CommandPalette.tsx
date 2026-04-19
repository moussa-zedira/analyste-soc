"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";

/* ------------------------------------------------------------------ */
/*  Navigation items (mirrored from Sidebar)                          */
/* ------------------------------------------------------------------ */

const NAV_PAGES = [
  // SIEM Core
  { href: "/", label: "Dashboard" },
  { href: "/search", label: "Search (CQL)" },
  { href: "/events", label: "Events" },
  { href: "/incidents", label: "Incidents" },
  { href: "/sources", label: "Log Sources" },
  { href: "/hunting", label: "Threat Hunting" },
  { href: "/ioc", label: "IOC Management" },
  { href: "/threat-intel", label: "Threat Intel" },
  { href: "/alerts", label: "Alert Channels" },
  // Red Team
  { href: "/redteam/console", label: "Red Team Console" },
  { href: "/redteam/phishing", label: "Phishing Campaigns" },
  { href: "/redteam/bloodhound", label: "BloodHound AD" },
  { href: "/pentest/c2", label: "C2 Sliver" },
  // OSINT / Recon
  { href: "/recon", label: "OSINT Recon" },
  { href: "/pentest/subdomain", label: "Sous-domaines" },
  { href: "/pentest/crawler", label: "Web Crawler" },
  { href: "/pentest/netscan", label: "Net Scanner" },
  // Pentest Web
  { href: "/pentest/pipeline", label: "Pipeline Auto" },
  { href: "/pentest/sqli", label: "SQLi Engine" },
  { href: "/pentest/xss-engine", label: "XSS Engine" },
  { href: "/pentest/brute", label: "Brute Force" },
  // IA
  { href: "/ai/triage", label: "AI Triage" },
  { href: "/ai/rag", label: "AI RAG Assistant" },
  { href: "/ai/rule-gen", label: "AI Rule Generator" },
  // SOAR
  { href: "/soar/playbooks", label: "SOAR Playbooks" },
  { href: "/soar/executions", label: "SOAR Executions" },
  // Doc + Admin
  { href: "/pentest/docs", label: "Pentest Docs" },
  { href: "/assets", label: "Assets" },
  { href: "/reports", label: "Reports" },
  { href: "/admin", label: "Admin" },
];

/* ------------------------------------------------------------------ */
/*  Quick actions                                                      */
/* ------------------------------------------------------------------ */

interface QuickAction {
  id: string;
  label: string;
  description: string;
  action: () => void;
}

/* ------------------------------------------------------------------ */
/*  Result types                                                       */
/* ------------------------------------------------------------------ */

type ResultCategory = "recent" | "page" | "action";

interface PaletteResult {
  id: string;
  label: string;
  description?: string;
  category: ResultCategory;
  href?: string;
  action?: () => void;
}

/* ------------------------------------------------------------------ */
/*  Fuzzy matching helper                                              */
/* ------------------------------------------------------------------ */

function fuzzyMatch(
  query: string,
  text: string,
): { match: boolean; score: number; indices: number[] } {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  const indices: number[] = [];
  let qi = 0;
  let score = 0;
  let lastIdx = -1;

  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) {
      indices.push(ti);
      if (lastIdx >= 0 && ti === lastIdx + 1) score += 3;
      if (ti === 0 || t[ti - 1] === " " || t[ti - 1] === "/") score += 2;
      score += 1;
      lastIdx = ti;
      qi++;
    }
  }

  return { match: qi === q.length, score, indices };
}

/* ------------------------------------------------------------------ */
/*  Highlighted text                                                   */
/* ------------------------------------------------------------------ */

function HighlightedText({
  text,
  indices,
}: {
  text: string;
  indices: number[];
}) {
  const set = new Set(indices);
  return (
    <span>
      {text.split("").map((ch, i) =>
        set.has(i) ? (
          <span key={i} className="text-cyan-glow font-semibold">
            {ch}
          </span>
        ) : (
          <span key={i}>{ch}</span>
        ),
      )}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Category icon                                                      */
/* ------------------------------------------------------------------ */

function CategoryIcon({ category }: { category: ResultCategory }) {
  if (category === "page") {
    return (
      <svg
        className="h-4 w-4 shrink-0 text-cyan-glow/60"
        fill="none"
        viewBox="0 0 24 24"
        strokeWidth={1.5}
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25"
        />
      </svg>
    );
  }
  if (category === "action") {
    return (
      <svg
        className="h-4 w-4 shrink-0 text-cyan-glow/60"
        fill="none"
        viewBox="0 0 24 24"
        strokeWidth={1.5}
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z"
        />
      </svg>
    );
  }
  return (
    <svg
      className="h-4 w-4 shrink-0 text-cyan-glow/60"
      fill="none"
      viewBox="0 0 24 24"
      strokeWidth={1.5}
      stroke="currentColor"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"
      />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Recent pages (localStorage)                                        */
/* ------------------------------------------------------------------ */

const RECENT_KEY = "cmd_palette_recent";
const MAX_RECENT = 5;

function getRecent(): string[] {
  if (typeof window === "undefined") return [];
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]") as string[];
  } catch {
    return [];
  }
}

function pushRecent(href: string) {
  const list = getRecent().filter((h) => h !== href);
  list.unshift(href);
  localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, MAX_RECENT)));
}

/* ------------------------------------------------------------------ */
/*  Main component                                                     */
/* ------------------------------------------------------------------ */

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const router = useRouter();

  /* -- Quick actions ------------------------------------------------ */
  const quickActions: QuickAction[] = useMemo(
    () => [
      {
        id: "action-run-pipeline",
        label: "Run Pentest Pipeline",
        description: "Launch the automated pentest pipeline",
        action: () => router.push("/pentest/pipeline"),
      },
      {
        id: "action-new-incident",
        label: "Open Incidents",
        description: "Review active SOC incidents",
        action: () => router.push("/incidents"),
      },
      {
        id: "action-export-data",
        label: "Export Data",
        description: "Export current events to CSV / JSON",
        action: () => {
          window.dispatchEvent(new CustomEvent("cmd:export-data"));
        },
      },
      {
        id: "action-clear-notifications",
        label: "Clear Notifications",
        description: "Dismiss all notification badges",
        action: () => {
          window.dispatchEvent(new CustomEvent("cmd:clear-notifications"));
        },
      },
    ],
    [router],
  );

  /* -- Build results ------------------------------------------------ */
  const results: (PaletteResult & { matchIndices: number[] })[] = useMemo(() => {
    const out: (PaletteResult & { matchIndices: number[] })[] = [];

    if (query.trim() === "") {
      const recent = getRecent();
      recent.forEach((href) => {
        const nav = NAV_PAGES.find((n) => n.href === href);
        if (nav) {
          out.push({
            id: "recent-" + href,
            label: nav.label,
            category: "recent",
            href,
            matchIndices: [],
          });
        }
      });
      quickActions.forEach((a) => {
        out.push({
          id: a.id,
          label: a.label,
          description: a.description,
          category: "action",
          action: a.action,
          matchIndices: [],
        });
      });
      const recentSet = new Set(recent);
      NAV_PAGES.filter((p) => !recentSet.has(p.href))
        .slice(0, 8)
        .forEach((p) => {
          out.push({
            id: "page-" + p.href,
            label: p.label,
            category: "page",
            href: p.href,
            matchIndices: [],
          });
        });
      return out;
    }

    const scored: {
      result: PaletteResult & { matchIndices: number[] };
      score: number;
    }[] = [];

    NAV_PAGES.forEach((p) => {
      const fm = fuzzyMatch(query, p.label);
      if (fm.match) {
        scored.push({
          result: {
            id: "page-" + p.href,
            label: p.label,
            category: "page",
            href: p.href,
            matchIndices: fm.indices,
          },
          score: fm.score,
        });
      }
    });

    quickActions.forEach((a) => {
      const fm = fuzzyMatch(query, a.label);
      if (fm.match) {
        scored.push({
          result: {
            id: a.id,
            label: a.label,
            description: a.description,
            category: "action",
            action: a.action,
            matchIndices: fm.indices,
          },
          score: fm.score,
        });
      }
    });

    scored.sort((a, b) => b.score - a.score);
    return scored.map((s) => s.result);
  }, [query, quickActions]);

  /* -- Group results by category ------------------------------------ */
  const grouped = useMemo(() => {
    const map: Record<ResultCategory, typeof results> = {
      recent: [],
      page: [],
      action: [],
    };
    results.forEach((r) => map[r.category].push(r));
    return map;
  }, [results]);

  const flatResults = useMemo(() => {
    const order: ResultCategory[] = ["recent", "page", "action"];
    return order.flatMap((cat) => grouped[cat]);
  }, [grouped]);

  /* -- Close -------------------------------------------------------- */
  const handleClose = useCallback(() => setOpen(false), []);

  /* -- Select a result ---------------------------------------------- */
  const selectResult = useCallback(
    (r: PaletteResult) => {
      handleClose();
      if (r.href) {
        pushRecent(r.href);
        router.push(r.href);
      } else if (r.action) {
        r.action();
      }
    },
    [handleClose, router],
  );

  /* -- Global keyboard shortcut (Ctrl+K / Cmd+K) ------------------- */
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((prev) => {
          if (!prev) {
            setQuery("");
            setActiveIdx(0);
          }
          return !prev;
        });
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  /* -- Focus input when opened -------------------------------------- */
  useEffect(() => {
    if (open) {
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  /* -- Reset active index when query changes ------------------------ */
  useEffect(() => {
    setActiveIdx(0);
  }, [query]);

  /* -- Scroll active item into view --------------------------------- */
  useEffect(() => {
    if (!listRef.current) return;
    const active = listRef.current.querySelector("[data-active='true']");
    active?.scrollIntoView({ block: "nearest" });
  }, [activeIdx]);

  /* -- Keyboard nav inside palette ---------------------------------- */
  const onInputKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIdx((i) => Math.min(i + 1, flatResults.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (flatResults[activeIdx]) selectResult(flatResults[activeIdx]);
    } else if (e.key === "Escape") {
      handleClose();
    }
  };

  /* ---------------------------------------------------------------- */
  /*  Render                                                           */
  /* ---------------------------------------------------------------- */

  const categoryLabels: Record<ResultCategory, string> = {
    recent: "Recent",
    page: "Pages",
    action: "Actions",
  };

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            className="fixed inset-0 z-[9998] bg-space-deep/60 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            onClick={handleClose}
          />

          {/* Palette panel */}
          <motion.div
            className="fixed inset-x-0 top-[12%] z-[9999] mx-auto w-full max-w-xl px-4"
            initial={{ opacity: 0, y: -20, scale: 0.96, filter: "blur(4px)" }}
            animate={{ opacity: 1, y: 0, scale: 1, filter: "blur(0px)" }}
            exit={{ opacity: 0, y: -12, scale: 0.97, filter: "blur(4px)" }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="glass-panel overflow-hidden shadow-cyan-glow">
              {/* Search input row */}
              <div className="flex items-center gap-3 border-b border-cyan-glow/10 px-4 py-3">
                <svg
                  className="h-5 w-5 shrink-0 text-cyan-glow/50"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"
                  />
                </svg>
                <input
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={onInputKeyDown}
                  placeholder="Search pages, actions..."
                  className="flex-1 bg-transparent text-sm text-gray-100 placeholder-cyan-muted/50 outline-none font-mono"
                  autoComplete="off"
                  spellCheck={false}
                />
                <kbd className="hidden sm:inline-flex items-center gap-1 rounded border border-cyan-glow/15 bg-space-mid/50 px-1.5 py-0.5 text-[10px] font-mono text-cyan-glow/40">
                  ESC
                </kbd>
              </div>

              {/* Results list */}
              <div ref={listRef} className="max-h-[360px] overflow-y-auto p-2">
                {flatResults.length === 0 && query.trim() !== "" && (
                  <div className="px-3 py-8 text-center text-sm text-cyan-muted/40 font-mono">
                    No results for &ldquo;{query}&rdquo;
                  </div>
                )}

                {(["recent", "page", "action"] as ResultCategory[]).map(
                  (cat) => {
                    const items = grouped[cat];
                    if (items.length === 0) return null;
                    return (
                      <div key={cat} className="mb-1">
                        <div className="hud-label px-3 pb-1 pt-2">
                          {categoryLabels[cat]}
                        </div>
                        {items.map((r) => {
                          const idx = flatResults.indexOf(r);
                          const isActive = idx === activeIdx;
                          return (
                            <button
                              key={r.id}
                              data-active={isActive}
                              onClick={() => selectResult(r)}
                              onMouseEnter={() => setActiveIdx(idx)}
                              className={
                                "flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors " +
                                (isActive
                                  ? "bg-cyan-glow/10 text-cyan-glow"
                                  : "text-gray-300 hover:bg-cyan-glow/5")
                              }
                            >
                              <CategoryIcon category={r.category} />
                              <div className="min-w-0 flex-1">
                                <div className="truncate font-mono text-sm">
                                  {r.matchIndices.length > 0 ? (
                                    <HighlightedText
                                      text={r.label}
                                      indices={r.matchIndices}
                                    />
                                  ) : (
                                    r.label
                                  )}
                                </div>
                                {r.description && (
                                  <div className="truncate text-xs text-cyan-muted/40 mt-0.5">
                                    {r.description}
                                  </div>
                                )}
                              </div>
                              {r.href && (
                                <span className="shrink-0 text-[10px] font-mono text-cyan-glow/25">
                                  {r.href}
                                </span>
                              )}
                              {isActive && (
                                <kbd className="shrink-0 rounded border border-cyan-glow/15 bg-space-mid/50 px-1 py-0.5 text-[10px] font-mono text-cyan-glow/40">
                                  Enter
                                </kbd>
                              )}
                            </button>
                          );
                        })}
                      </div>
                    );
                  },
                )}
              </div>

              {/* Footer with keyboard hints */}
              <div className="flex items-center justify-between border-t border-cyan-glow/10 px-4 py-2">
                <div className="flex items-center gap-3 text-[10px] font-mono text-cyan-glow/30">
                  <span className="flex items-center gap-1">
                    <kbd className="rounded border border-cyan-glow/15 bg-space-mid/50 px-1 py-0.5">
                      &uarr;&darr;
                    </kbd>
                    navigate
                  </span>
                  <span className="flex items-center gap-1">
                    <kbd className="rounded border border-cyan-glow/15 bg-space-mid/50 px-1 py-0.5">
                      &crarr;
                    </kbd>
                    select
                  </span>
                  <span className="flex items-center gap-1">
                    <kbd className="rounded border border-cyan-glow/15 bg-space-mid/50 px-1 py-0.5">
                      esc
                    </kbd>
                    close
                  </span>
                </div>
                <span className="hud-label text-[9px]">Command Palette</span>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
