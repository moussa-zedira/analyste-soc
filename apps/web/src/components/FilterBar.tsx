"use client";

import type { ReactNode } from "react";

/** Barre de filtres avec bouton de reinitialisation et compteur de filtres actifs. */
export function FilterBar({
  children,
  onReset,
  activeCount,
}: {
  children: ReactNode;
  onReset: () => void;
  activeCount?: number;
}) {
  return (
    <div className="glass-panel flex flex-wrap items-end gap-3 p-4">
      {children}
      <div className="flex items-center gap-2">
        {activeCount != null && activeCount > 0 && (
          <span className="inline-flex items-center rounded-full border border-cyan-glow/20 bg-cyan-glow/10 px-2 py-0.5 text-xs font-medium text-cyan-glow">
            {activeCount} active
          </span>
        )}
        <button
          onClick={onReset}
          className="rounded-md border border-cyan-glow/20 bg-space-mid/50 px-3 py-1.5 text-[10px] font-bold tracking-wider text-gray-400 transition-all hover:border-cyan-glow/40 hover:bg-cyan-glow/10 hover:text-cyan-glow active:scale-95"
        >
          RESET
        </button>
      </div>
    </div>
  );
}

/** Liste deroulante de filtre avec label et options configurables. */
export function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
}) {
  const isActive = value !== "";
  return (
    <label className="flex flex-col gap-1.5">
      <span className="hud-label">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`rounded-md border px-3 py-2 text-sm outline-none transition-colors bg-space-dark ${
          isActive
            ? "border-cyan-glow/40 text-cyan-glow"
            : "border-cyan-glow/15 text-gray-300"
        } focus:border-cyan-glow/50 focus:ring-1 focus:ring-cyan-glow/20`}
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Champ de saisie de filtre texte avec bouton d'effacement. */
export function FilterInput({
  label,
  value,
  placeholder,
  onChange,
}: {
  label: string;
  value: string;
  placeholder?: string;
  onChange: (v: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="hud-label">{label}</span>
      <div className="relative">
        <input
          type="text"
          value={value}
          placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
          className="rounded-md border border-cyan-glow/15 bg-space-dark px-3 py-2 pr-7 text-sm text-gray-300 placeholder-gray-600 outline-none transition-colors focus:border-cyan-glow/50 focus:ring-1 focus:ring-cyan-glow/20"
        />
        {value && (
          <button
            type="button"
            onClick={() => onChange("")}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 transition-colors hover:text-cyan-glow"
            aria-label="Clear filter"
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>
    </label>
  );
}
