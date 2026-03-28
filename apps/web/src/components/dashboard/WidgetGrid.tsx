"use client";

import {
  useState,
  useCallback,
  useEffect,
  useRef,
  type DragEvent,
  type ReactElement,
} from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Widget, sizeToGridSpan, type WidgetSize } from "./Widget";

/* ── Widget registry types ── */

export interface WidgetConfig {
  id: string;
  type: string;
  title: string;
  size: WidgetSize;
  visible: boolean;
}

export interface WidgetRegistryEntry {
  type: string;
  title: string;
  defaultSize: WidgetSize;
  component: React.ComponentType<{ refreshKey: number }>;
}

const STORAGE_KEY = "cyberdef-dashboard-layout";

interface WidgetGridProps {
  registry: WidgetRegistryEntry[];
  defaultLayout: WidgetConfig[];
}

/** Main widget grid with native HTML5 drag-and-drop reordering */
export function WidgetGrid({ registry, defaultLayout }: WidgetGridProps) {
  const [layout, setLayout] = useState<WidgetConfig[]>(() => {
    if (typeof window === "undefined") return defaultLayout;
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as WidgetConfig[];
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch { /* ignore */ }
    return defaultLayout;
  });

  const [editMode, setEditMode] = useState(false);
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [dragOverId, setDragOverId] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [showAddMenu, setShowAddMenu] = useState(false);
  const addMenuRef = useRef<HTMLDivElement>(null);

  // Persist layout to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
    } catch { /* ignore */ }
  }, [layout]);

  // Auto-refresh every 10s
  useEffect(() => {
    const t = setInterval(() => setRefreshKey((k) => k + 1), 10_000);
    return () => clearInterval(t);
  }, []);

  // Close add menu on outside click
  useEffect(() => {
    if (!showAddMenu) return;
    const handler = (e: MouseEvent) => {
      if (addMenuRef.current && !addMenuRef.current.contains(e.target as Node)) {
        setShowAddMenu(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showAddMenu]);

  /* ── Drag handlers ── */

  const handleDragStart = useCallback((e: DragEvent<HTMLDivElement>, id: string) => {
    setDraggedId(id);
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", id);
    // Make the drag image semi-transparent
    if (e.currentTarget) {
      e.currentTarget.style.opacity = "0.4";
    }
  }, []);

  const handleDragEnd = useCallback((e: DragEvent<HTMLDivElement>) => {
    setDraggedId(null);
    setDragOverId(null);
    if (e.currentTarget) {
      e.currentTarget.style.opacity = "1";
    }
  }, []);

  const handleDragOver = useCallback((e: DragEvent<HTMLDivElement>, targetId: string) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    if (targetId !== draggedId) {
      setDragOverId(targetId);
    }
  }, [draggedId]);

  const handleDragLeave = useCallback(() => {
    setDragOverId(null);
  }, []);

  const handleDrop = useCallback((e: DragEvent<HTMLDivElement>, targetId: string) => {
    e.preventDefault();
    const sourceId = e.dataTransfer.getData("text/plain");
    if (!sourceId || sourceId === targetId) {
      setDragOverId(null);
      return;
    }

    setLayout((prev) => {
      const newLayout = [...prev];
      const sourceIdx = newLayout.findIndex((w) => w.id === sourceId);
      const targetIdx = newLayout.findIndex((w) => w.id === targetId);
      if (sourceIdx === -1 || targetIdx === -1) return prev;

      // Swap positions
      const [moved] = newLayout.splice(sourceIdx, 1);
      newLayout.splice(targetIdx, 0, moved);
      return newLayout;
    });

    setDraggedId(null);
    setDragOverId(null);
  }, []);

  /* ── Widget CRUD ── */

  const handleRemove = useCallback((id: string) => {
    setLayout((prev) => prev.map((w) => w.id === id ? { ...w, visible: false } : w));
  }, []);

  const handleResize = useCallback((id: string, newSize: WidgetSize) => {
    setLayout((prev) => prev.map((w) => w.id === id ? { ...w, size: newSize } : w));
  }, []);

  const handleResetLayout = useCallback(() => {
    setLayout(defaultLayout);
    try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
  }, [defaultLayout]);

  const handleAddWidget = useCallback((type: string) => {
    const entry = registry.find((r) => r.type === type);
    if (!entry) return;

    setLayout((prev) => {
      // Check if it's already in layout but hidden
      const existing = prev.find((w) => w.type === type);
      if (existing) {
        return prev.map((w) => w.type === type ? { ...w, visible: true } : w);
      }
      // Add new
      return [
        ...prev,
        {
          id: `${type}-${Date.now()}`,
          type: entry.type,
          title: entry.title,
          size: entry.defaultSize,
          visible: true,
        },
      ];
    });
    setShowAddMenu(false);
  }, [registry]);

  /* ── Derive visible layout ── */
  const visibleWidgets = layout.filter((w) => w.visible);
  const hiddenTypes = layout
    .filter((w) => !w.visible)
    .map((w) => w.type);
  const addableWidgets = registry.filter(
    (r) => hiddenTypes.includes(r.type) || !layout.some((w) => w.type === r.type),
  );

  /* ── Component lookup ── */
  const getComponent = (type: string) => {
    return registry.find((r) => r.type === type)?.component;
  };

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setEditMode((v) => !v)}
            className={`rounded-md px-4 py-2 text-[10px] font-bold tracking-widest transition-all duration-300 ${
              editMode
                ? "border border-cyan-glow/50 bg-cyan-glow/20 text-cyan-glow shadow-cyan-md"
                : "border border-gray-700 bg-space-mid/50 text-gray-400 hover:border-cyan-glow/20 hover:text-gray-300"
            }`}
          >
            {editMode ? "DONE EDITING" : "EDIT LAYOUT"}
          </button>

          {editMode && (
            <>
              <button
                onClick={handleResetLayout}
                className="rounded-md border border-gray-700 bg-space-mid/50 px-4 py-2 text-[10px] font-bold tracking-widest text-gray-400 transition-all hover:border-red-500/30 hover:text-red-400"
              >
                RESET LAYOUT
              </button>

              <div className="relative" ref={addMenuRef}>
                <button
                  onClick={() => setShowAddMenu((v) => !v)}
                  disabled={addableWidgets.length === 0}
                  className="rounded-md border border-gray-700 bg-space-mid/50 px-4 py-2 text-[10px] font-bold tracking-widest text-gray-400 transition-all hover:border-cyan-glow/20 hover:text-cyan-glow disabled:opacity-30"
                >
                  + ADD WIDGET
                </button>

                <AnimatePresence>
                  {showAddMenu && addableWidgets.length > 0 && (
                    <motion.div
                      initial={{ opacity: 0, y: -8, scale: 0.95 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, y: -8, scale: 0.95 }}
                      transition={{ duration: 0.15 }}
                      className="absolute left-0 top-full z-50 mt-2 min-w-[200px] rounded-lg border border-cyan-glow/20 bg-space-dark/95 p-2 shadow-2xl backdrop-blur-md"
                    >
                      {addableWidgets.map((entry) => (
                        <button
                          key={entry.type}
                          onClick={() => handleAddWidget(entry.type)}
                          className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-[10px] tracking-wider text-gray-400 transition-colors hover:bg-cyan-glow/10 hover:text-cyan-glow"
                        >
                          <span className="text-cyan-glow/50">+</span>
                          <span className="font-bold">{entry.title}</span>
                          <span className="ml-auto text-[8px] text-gray-600">{entry.defaultSize}</span>
                        </button>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </>
          )}
        </div>

        {editMode && (
          <p className="text-[9px] tracking-widest text-cyan-glow/30">
            DRAG WIDGETS TO REORDER // CLICK RESIZE TO CHANGE SIZE
          </p>
        )}
      </div>

      {/* Grid */}
      <div
        className="grid gap-4 transition-all duration-300"
        style={{
          gridTemplateColumns: "repeat(var(--grid-cols), minmax(0, 1fr))",
        }}
      >
        <style>{`
          :root {
            --grid-cols: 1;
          }
          @media (min-width: 768px) {
            :root { --grid-cols: 2; }
          }
          @media (min-width: 1280px) {
            :root { --grid-cols: 4; }
          }
        `}</style>

        <AnimatePresence mode="popLayout">
          {visibleWidgets.map((widget) => {
            const Comp = getComponent(widget.type);
            if (!Comp) return null;

            const span = sizeToGridSpan(widget.size);
            const isDraggedOver = dragOverId === widget.id;

            return (
              <motion.div
                key={widget.id}
                layout
                transition={{ duration: 0.3, ease: [0.25, 0.46, 0.45, 0.94] }}
                style={{
                  gridColumn: `span ${span.col}`,
                  gridRow: `span ${span.row}`,
                }}
                className={`relative transition-shadow duration-300 ${
                  isDraggedOver && editMode
                    ? "ring-2 ring-cyan-glow/60 shadow-cyan-glow rounded-lg"
                    : ""
                } ${draggedId === widget.id ? "opacity-40" : ""}`}
                onDragOver={(e) => handleDragOver(e, widget.id)}
                onDragLeave={handleDragLeave}
                onDrop={(e) => handleDrop(e, widget.id)}
              >
                {/* Cyan glow overlay when dragging over */}
                {isDraggedOver && editMode && (
                  <div className="pointer-events-none absolute inset-0 z-10 rounded-lg bg-cyan-glow/5 ring-2 ring-cyan-glow/40 animate-pulse-glow" />
                )}

                <Widget
                  id={widget.id}
                  title={widget.title}
                  size={widget.size}
                  editMode={editMode}
                  onRemove={handleRemove}
                  onResize={handleResize}
                  onDragStart={handleDragStart}
                  onDragEnd={handleDragEnd}
                >
                  <Comp refreshKey={refreshKey} />
                </Widget>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </div>
  );
}
