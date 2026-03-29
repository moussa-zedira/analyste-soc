"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export interface Suggestion {
  text: string;
  type: "field" | "command" | "operator" | "keyword" | "value" | "function";
  description: string;
  icon: string;
}

interface CQLAutocompleteProps {
  suggestions: Suggestion[];
  position: { x: number; y: number };
  onSelect: (suggestion: Suggestion) => void;
  onDismiss: () => void;
  visible: boolean;
}

/* ------------------------------------------------------------------ */
/*  Type badge colors                                                  */
/* ------------------------------------------------------------------ */

const TYPE_COLORS: Record<string, string> = {
  field: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  command: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
  operator: "bg-orange-500/20 text-orange-300 border-orange-500/30",
  keyword: "bg-cyan-500/20 text-cyan-300 border-cyan-500/30",
  value: "bg-green-500/20 text-green-300 border-green-500/30",
  function: "bg-pink-500/20 text-pink-300 border-pink-500/30",
};

/* ------------------------------------------------------------------ */
/*  Icon SVGs                                                          */
/* ------------------------------------------------------------------ */

function SuggestionIcon({ type, icon }: { type: string; icon: string }) {
  if (icon === "globe" || type === "field") {
    if (icon === "globe") {
      return (
        <svg className="h-3.5 w-3.5 text-blue-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
        </svg>
      );
    }
    if (icon === "clock") {
      return (
        <svg className="h-3.5 w-3.5 text-blue-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      );
    }
    if (icon === "hash") {
      return (
        <svg className="h-3.5 w-3.5 text-blue-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 8.25h15m-16.5 7.5h15m-1.8-13.5l-3.9 19.5m-2.1-19.5l-3.9 19.5" />
        </svg>
      );
    }
    return (
      <svg className="h-3.5 w-3.5 text-blue-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 01.865-.501 48.172 48.172 0 003.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z" />
      </svg>
    );
  }

  if (type === "command") {
    return (
      <svg className="h-3.5 w-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
      </svg>
    );
  }

  if (type === "operator") {
    return (
      <svg className="h-3.5 w-3.5 text-orange-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 6h9.75M10.5 6a1.5 1.5 0 11-3 0m3 0a1.5 1.5 0 10-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-9.75 0h9.75" />
      </svg>
    );
  }

  if (type === "keyword") {
    return (
      <svg className="h-3.5 w-3.5 text-cyan-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.568 3H5.25A2.25 2.25 0 003 5.25v4.318c0 .597.237 1.17.659 1.591l9.581 9.581c.699.699 1.78.872 2.607.33a18.095 18.095 0 005.223-5.223c.542-.827.369-1.908-.33-2.607L11.16 3.66A2.25 2.25 0 009.568 3z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 6h.008v.008H6V6z" />
      </svg>
    );
  }

  if (type === "function") {
    return (
      <svg className="h-3.5 w-3.5 text-pink-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M4.745 3A23.933 23.933 0 003 12c0 3.183.62 6.22 1.745 9M19.255 3C20.38 5.78 21 8.817 21 12s-.62 6.22-1.745 9m-13.46-2.25h.008v.008h-.008v-.008zm3.75 0h.008v.008h-.008v-.008zm3.75 0h.008v.008h-.008v-.008zm3.75 0h.008v.008h-.008v-.008zm-11.25-3.75h.008v.008h-.008v-.008zm3.75 0h.008v.008h-.008v-.008zm3.75 0h.008v.008h-.008v-.008zm3.75 0h.008v.008h-.008v-.008zm-11.25-3.75h.008v.008h-.008V9zm3.75 0h.008v.008h-.008V9zm3.75 0h.008v.008h-.008V9zm3.75 0h.008v.008h-.008V9z" />
      </svg>
    );
  }

  return (
    <svg className="h-3.5 w-3.5 text-gray-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export function CQLAutocomplete({
  suggestions,
  position,
  onSelect,
  onDismiss,
  visible,
}: CQLAutocompleteProps) {
  const [activeIdx, setActiveIdx] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  // Reset active index when suggestions change
  useEffect(() => {
    setActiveIdx(0);
  }, [suggestions]);

  // Global keyboard handler
  useEffect(() => {
    if (!visible) return;

    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        e.stopPropagation();
        setActiveIdx((i) => Math.min(i + 1, suggestions.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        e.stopPropagation();
        setActiveIdx((i) => Math.max(i - 1, 0));
      } else if (e.key === "Tab" || e.key === "Enter") {
        e.preventDefault();
        e.stopPropagation();
        if (suggestions[activeIdx]) {
          onSelect(suggestions[activeIdx]);
        }
      } else if (e.key === "Escape") {
        e.preventDefault();
        onDismiss();
      }
    }

    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [visible, suggestions, activeIdx, onSelect, onDismiss]);

  // Scroll active into view
  useEffect(() => {
    if (!listRef.current) return;
    const el = listRef.current.querySelector(`[data-idx="${activeIdx}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [activeIdx]);

  if (!visible || suggestions.length === 0) return null;

  return (
    <div
      className="absolute z-50 w-72 overflow-hidden rounded-lg border border-cyan-glow/20 bg-space-deep/95 shadow-lg shadow-cyan-glow/5 backdrop-blur-xl"
      style={{
        top: position.y,
        left: Math.max(0, position.x),
      }}
    >
      <div ref={listRef} className="max-h-[280px] overflow-y-auto py-1">
        {suggestions.map((s, idx) => (
          <button
            key={`${s.type}-${s.text}`}
            data-idx={idx}
            onClick={() => onSelect(s)}
            onMouseEnter={() => setActiveIdx(idx)}
            className={`flex w-full items-center gap-2.5 px-3 py-2 text-left transition-colors ${
              idx === activeIdx
                ? "bg-cyan-glow/10 text-gray-100"
                : "text-gray-400 hover:bg-cyan-glow/5"
            }`}
          >
            <SuggestionIcon type={s.type} icon={s.icon} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span
                  className="truncate font-mono text-[12px]"
                  style={{ fontFamily: "'JetBrains Mono', monospace" }}
                >
                  {s.text}
                </span>
                <span
                  className={`shrink-0 rounded-full border px-1.5 py-0 text-[9px] font-semibold uppercase tracking-wider ${
                    TYPE_COLORS[s.type] || "bg-gray-500/20 text-gray-400 border-gray-500/30"
                  }`}
                >
                  {s.type}
                </span>
              </div>
              <p className="truncate text-[10px] text-gray-600">{s.description}</p>
            </div>
            {idx === activeIdx && (
              <kbd className="shrink-0 rounded border border-cyan-glow/15 bg-space-mid/50 px-1 py-0.5 text-[9px] font-mono text-cyan-glow/40">
                Tab
              </kbd>
            )}
          </button>
        ))}
      </div>
      <div className="flex items-center justify-between border-t border-cyan-glow/10 px-3 py-1.5">
        <span className="text-[9px] font-mono text-gray-600">
          {suggestions.length} suggestion{suggestions.length !== 1 ? "s" : ""}
        </span>
        <span className="flex items-center gap-2 text-[9px] font-mono text-gray-600">
          <kbd className="rounded border border-cyan-glow/10 bg-space-mid/40 px-1 py-0.5">
            ↑↓
          </kbd>
          nav
          <kbd className="rounded border border-cyan-glow/10 bg-space-mid/40 px-1 py-0.5">
            Tab
          </kbd>
          accept
        </span>
      </div>
    </div>
  );
}
