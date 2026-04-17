"use client";

import * as React from "react";

export interface HudTabItem<T extends string = string> {
  id: T;
  label: React.ReactNode;
  count?: number | string;
  tone?: "cyan" | "matrix" | "alert" | "warn";
}

export interface HudTabsProps<T extends string = string> {
  items: ReadonlyArray<HudTabItem<T>>;
  value: T;
  onChange: (id: T) => void;
  className?: string;
}

const ACTIVE_TONE: Record<NonNullable<HudTabItem["tone"]>, string> = {
  cyan: "border-cyan-glow bg-cyan-glow/15 text-cyan-glow shadow-cyan-md",
  matrix: "border-matrix-green bg-matrix-green/15 text-matrix-green shadow-matrix-glow",
  alert: "border-neon-pink bg-neon-pink/15 text-neon-pink shadow-alert-glow",
  warn: "border-neon-orange bg-neon-orange/15 text-neon-orange shadow-warn-glow",
};

export function HudTabs<T extends string = string>({
  items,
  value,
  onChange,
  className = "",
}: HudTabsProps<T>) {
  return (
    <div role="tablist" className={`flex flex-wrap gap-2 ${className}`}>
      {items.map((it) => {
        const tone = it.tone ?? "cyan";
        const isActive = it.id === value;
        const cls = isActive
          ? ACTIVE_TONE[tone]
          : "border-cyan-glow/20 bg-black/40 text-cyan-glow/60 hover:border-cyan-glow/40 hover:text-cyan-glow/80";
        return (
          <button
            key={it.id}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(it.id)}
            className={`inline-flex items-center gap-2 rounded border px-3 py-1.5 text-[11px] uppercase tracking-widest transition-all duration-150 cursor-pointer focus-visible:ring-2 focus-visible:ring-cyan-glow/60 focus-visible:ring-offset-2 focus-visible:ring-offset-space-deep ${cls}`}
          >
            <span>{it.label}</span>
            {it.count !== undefined && (
              <span className="rounded bg-black/40 px-1.5 py-0.5 font-mono text-[9px] opacity-80">
                {it.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
