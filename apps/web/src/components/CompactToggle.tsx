"use client";

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";

/* ------------------------------------------------------------------ */
/*  Density modes                                                      */
/* ------------------------------------------------------------------ */
export type DensityMode = "comfortable" | "compact" | "dense";

const MODES: { mode: DensityMode; label: string; icon: string; rows: number }[] = [
  {
    mode: "comfortable",
    label: "Comfortable",
    icon: "bars-wide",
    rows: 3,
  },
  {
    mode: "compact",
    label: "Compact",
    icon: "bars-mid",
    rows: 4,
  },
  {
    mode: "dense",
    label: "Dense",
    icon: "bars-narrow",
    rows: 5,
  },
];

const LS_KEY = "cyberdef_density";
export const DENSITY_EVENT = "density-changed";

/* ------------------------------------------------------------------ */
/*  CSS class map for consumers                                        */
/* ------------------------------------------------------------------ */
export const DENSITY_CLASSES: Record<DensityMode, { cell: string; text: string; row: string }> = {
  comfortable: {
    cell: "px-4 py-3",
    text: "text-xs",
    row: "h-12",
  },
  compact: {
    cell: "px-3 py-2",
    text: "text-[11px]",
    row: "h-9",
  },
  dense: {
    cell: "px-2 py-1",
    text: "text-[10px]",
    row: "h-7",
  },
};

/* ------------------------------------------------------------------ */
/*  Hook for consuming density from any component                      */
/* ------------------------------------------------------------------ */
export function useDensity(): DensityMode {
  const [density, setDensity] = useState<DensityMode>("comfortable");

  useEffect(() => {
    const saved = localStorage.getItem(LS_KEY) as DensityMode | null;
    if (saved && ["comfortable", "compact", "dense"].includes(saved)) {
      setDensity(saved);
    }

    const handler = (e: Event) => {
      const mode = (e as CustomEvent<DensityMode>).detail;
      setDensity(mode);
    };
    window.addEventListener(DENSITY_EVENT, handler);
    return () => window.removeEventListener(DENSITY_EVENT, handler);
  }, []);

  return density;
}

/* ------------------------------------------------------------------ */
/*  Bar icon SVG                                                       */
/* ------------------------------------------------------------------ */
function DensityBars({ rows, active }: { rows: number; active: boolean }) {
  const barH = rows <= 3 ? 3 : rows <= 4 ? 2.5 : 2;
  const gap = rows <= 3 ? 3 : rows <= 4 ? 2 : 1.5;
  const totalH = rows * barH + (rows - 1) * gap;
  const startY = (16 - totalH) / 2;

  return (
    <svg className="h-4 w-4" viewBox="0 0 16 16" fill="none">
      {Array.from({ length: rows }).map((_, i) => (
        <rect
          key={i}
          x={2}
          y={startY + i * (barH + gap)}
          width={12}
          height={barH}
          rx={1}
          className={`transition-colors duration-200 ${
            active ? "fill-cyan-glow" : "fill-gray-600"
          }`}
        />
      ))}
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  CompactToggle component                                            */
/* ------------------------------------------------------------------ */
export function CompactToggle() {
  const [density, setDensity] = useState<DensityMode>("comfortable");
  const [showTooltip, setShowTooltip] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const saved = localStorage.getItem(LS_KEY) as DensityMode | null;
    if (saved && ["comfortable", "compact", "dense"].includes(saved)) {
      setDensity(saved);
    }
  }, []);

  const cycle = useCallback(() => {
    setDensity((prev) => {
      const order: DensityMode[] = ["comfortable", "compact", "dense"];
      const next = order[(order.indexOf(prev) + 1) % order.length];
      localStorage.setItem(LS_KEY, next);
      window.dispatchEvent(new CustomEvent(DENSITY_EVENT, { detail: next }));
      return next;
    });
  }, []);

  if (!mounted) return null;

  const current = MODES.find((m) => m.mode === density)!;

  return (
    <div
      className="relative"
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <motion.button
        onClick={cycle}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.9 }}
        className="flex items-center justify-center w-8 h-8 rounded-md border border-transparent hover:border-cyan-glow/15 hover:bg-cyan-glow/5 transition-all duration-200 group"
        title={`Table density: ${current.label}`}
      >
        <motion.div
          key={density}
          initial={{ scale: 0.7, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: "spring", stiffness: 400, damping: 20 }}
        >
          <DensityBars rows={current.rows} active={false} />
        </motion.div>
      </motion.button>

      {/* Tooltip */}
      {showTooltip && (
        <motion.div
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-50 px-2.5 py-1.5 rounded border border-cyan-glow/15 bg-space-dark/95 backdrop-blur-xl shadow-cyan-sm whitespace-nowrap"
        >
          <div className="text-[9px] font-bold tracking-widest text-cyan-glow/80 uppercase font-['Orbitron']">
            {current.label}
          </div>
          <div className="text-[8px] text-cyan-glow/30 tracking-wide mt-0.5">
            Table density
          </div>
          {/* Arrow */}
          <div className="absolute top-full left-1/2 -translate-x-1/2 w-0 h-0 border-l-[4px] border-r-[4px] border-t-[4px] border-l-transparent border-r-transparent border-t-cyan-glow/15" />
        </motion.div>
      )}
    </div>
  );
}
