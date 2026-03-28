"use client";

import { useState, type ReactNode, type DragEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";

export type WidgetSize = "1x1" | "2x1" | "1x2" | "2x2";

export interface WidgetProps {
  id: string;
  title: string;
  size: WidgetSize;
  children: ReactNode;
  onRemove?: (id: string) => void;
  onResize?: (id: string, size: WidgetSize) => void;
  editMode?: boolean;
  loading?: boolean;
  /** Called when drag starts on this widget */
  onDragStart?: (e: DragEvent<HTMLDivElement>, id: string) => void;
  onDragEnd?: (e: DragEvent<HTMLDivElement>) => void;
}

const SIZE_CYCLE: WidgetSize[] = ["1x1", "2x1", "1x2", "2x2"];

/** CSS grid span values for each widget size */
export function sizeToGridSpan(size: WidgetSize): { col: number; row: number } {
  switch (size) {
    case "1x1": return { col: 1, row: 1 };
    case "2x1": return { col: 2, row: 1 };
    case "1x2": return { col: 1, row: 2 };
    case "2x2": return { col: 2, row: 2 };
    default:    return { col: 1, row: 1 };
  }
}

export function Widget({
  id,
  title,
  size,
  children,
  onRemove,
  onResize,
  editMode = false,
  loading = false,
  onDragStart,
  onDragEnd,
}: WidgetProps) {
  const [minimized, setMinimized] = useState(false);

  const nextSize = () => {
    const idx = SIZE_CYCLE.indexOf(size);
    const next = SIZE_CYCLE[(idx + 1) % SIZE_CYCLE.length];
    onResize?.(id, next);
  };

  const handleDragStart = (e: DragEvent<HTMLDivElement>) => {
    if (!editMode) {
      e.preventDefault();
      return;
    }
    onDragStart?.(e, id);
  };

  return (
    <div
      className={`
        glass-panel hud-corners relative flex flex-col overflow-hidden
        transition-all duration-300 animate-hud-reveal
        ${editMode ? "border-dashed !border-cyan-glow/40 cursor-grab active:cursor-grabbing" : ""}
      `}
      draggable={editMode}
      onDragStart={handleDragStart}
      onDragEnd={onDragEnd}
    >
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-cyan-glow/10 px-3 py-2">
        {/* Drag handle - only visible in edit mode */}
        {editMode && (
          <div className="flex flex-col gap-[2px] cursor-grab opacity-50 hover:opacity-100 transition-opacity">
            <div className="flex gap-[2px]">
              <span className="block h-1 w-1 rounded-full bg-cyan-glow/60" />
              <span className="block h-1 w-1 rounded-full bg-cyan-glow/60" />
            </div>
            <div className="flex gap-[2px]">
              <span className="block h-1 w-1 rounded-full bg-cyan-glow/60" />
              <span className="block h-1 w-1 rounded-full bg-cyan-glow/60" />
            </div>
            <div className="flex gap-[2px]">
              <span className="block h-1 w-1 rounded-full bg-cyan-glow/60" />
              <span className="block h-1 w-1 rounded-full bg-cyan-glow/60" />
            </div>
          </div>
        )}

        <h3 className="hud-heading flex-1 text-[11px] font-semibold tracking-widest text-cyan-glow/80">
          {title}
        </h3>

        {/* Size label in edit mode */}
        {editMode && (
          <span className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-1.5 py-0.5 text-[8px] font-mono tracking-wider text-cyan-glow/50">
            {size}
          </span>
        )}

        {/* Action buttons */}
        <div className="flex items-center gap-1">
          {/* Resize button */}
          {editMode && onResize && (
            <button
              onClick={(e) => { e.stopPropagation(); nextSize(); }}
              className="rounded p-1 text-cyan-glow/40 transition-colors hover:bg-cyan-glow/10 hover:text-cyan-glow"
              title={`Resize (current: ${size})`}
            >
              <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
              </svg>
            </button>
          )}

          {/* Minimize/maximize */}
          <button
            onClick={() => setMinimized((v) => !v)}
            className="rounded p-1 text-cyan-glow/40 transition-colors hover:bg-cyan-glow/10 hover:text-cyan-glow"
            title={minimized ? "Maximize" : "Minimize"}
          >
            <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              {minimized ? (
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 8h16M4 16h16" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 12h-15" />
              )}
            </svg>
          </button>

          {/* Remove */}
          {editMode && onRemove && (
            <button
              onClick={(e) => { e.stopPropagation(); onRemove(id); }}
              className="rounded p-1 text-red-400/40 transition-colors hover:bg-red-500/10 hover:text-red-400"
              title="Remove widget"
            >
              <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>
      </div>

      {/* Body */}
      <AnimatePresence initial={false}>
        {!minimized && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="flex-1 overflow-hidden"
          >
            {loading ? (
              <div className="space-y-3 p-4">
                <div className="skeleton h-4 w-3/4" />
                <div className="skeleton h-4 w-1/2" />
                <div className="skeleton h-20 w-full" />
                <div className="skeleton h-4 w-2/3" />
              </div>
            ) : (
              <div className="h-full p-3">
                {children}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
