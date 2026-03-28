"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { WidgetGrid, type WidgetRegistryEntry, type WidgetConfig } from "@/components/dashboard";
import { runRules } from "@/lib/apiClient";
import { useWebSocket, type WsMessage } from "@/lib/useWebSocket";
import type { RulesRunResponse } from "@/lib/types";

/* ── Lazy widget imports ── */
import KPIWidget from "@/components/dashboard/widgets/KPIWidget";
import EventsWidget from "@/components/dashboard/widgets/EventsWidget";
import HeatmapWidget from "@/components/dashboard/widgets/HeatmapWidget";
import ThreatMapWidget from "@/components/dashboard/widgets/ThreatMapWidget";
import IncidentsWidget from "@/components/dashboard/widgets/IncidentsWidget";
import MLWidget from "@/components/dashboard/widgets/MLWidget";
import ThreatScoreWidget from "@/components/dashboard/widgets/ThreatScoreWidget";
import LiveFeedWidget from "@/components/dashboard/widgets/LiveFeedWidget";
import SystemWidget from "@/components/dashboard/widgets/SystemWidget";

/* ── Widget registry ── */
const WIDGET_REGISTRY: WidgetRegistryEntry[] = [
  { type: "kpi",          title: "KPI OVERVIEW",        defaultSize: "2x1", component: KPIWidget },
  { type: "events",       title: "EVENTS / MINUTE",     defaultSize: "2x1", component: EventsWidget },
  { type: "heatmap",      title: "ATTACK HEATMAP",      defaultSize: "2x1", component: HeatmapWidget },
  { type: "threat-map",   title: "THREAT MAP",          defaultSize: "2x1", component: ThreatMapWidget },
  { type: "incidents",    title: "OPEN INCIDENTS",       defaultSize: "1x1", component: IncidentsWidget },
  { type: "ml",           title: "ML DETECTION",         defaultSize: "1x1", component: MLWidget },
  { type: "threat-score", title: "TOP THREAT IPs",       defaultSize: "1x1", component: ThreatScoreWidget },
  { type: "live-feed",    title: "LIVE EVENT FEED",      defaultSize: "2x1", component: LiveFeedWidget },
  { type: "system",       title: "SYSTEM STATUS",        defaultSize: "1x1", component: SystemWidget },
];

const DEFAULT_LAYOUT: WidgetConfig[] = [
  { id: "kpi-1",          type: "kpi",          title: "KPI OVERVIEW",    size: "2x1", visible: true },
  { id: "system-1",       type: "system",       title: "SYSTEM STATUS",   size: "1x1", visible: true },
  { id: "incidents-1",    type: "incidents",     title: "OPEN INCIDENTS",  size: "1x1", visible: true },
  { id: "events-1",       type: "events",       title: "EVENTS / MINUTE", size: "2x1", visible: true },
  { id: "heatmap-1",      type: "heatmap",      title: "ATTACK HEATMAP",  size: "2x1", visible: true },
  { id: "ml-1",           type: "ml",           title: "ML DETECTION",    size: "1x1", visible: true },
  { id: "threat-score-1", type: "threat-score", title: "TOP THREAT IPs",  size: "1x1", visible: true },
  { id: "threat-map-1",   type: "threat-map",   title: "THREAT MAP",      size: "2x1", visible: true },
  { id: "live-feed-1",    type: "live-feed",    title: "LIVE EVENT FEED", size: "2x1", visible: true },
];

/* ── Animation variants ── */
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1, delayChildren: 0.05 },
  },
};

const sectionVariants = {
  hidden: { opacity: 0, y: 24 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] as const },
  },
};

/* ── Uptime formatter ── */
function formatUptime(now: Date, start: Date): string {
  const diff = Math.floor((now.getTime() - start.getTime()) / 1000);
  const h = Math.floor(diff / 3600).toString().padStart(2, "0");
  const m = Math.floor((diff % 3600) / 60).toString().padStart(2, "0");
  const s = (diff % 60).toString().padStart(2, "0");
  return `${h}:${m}:${s}`;
}

/** Command Center dashboard with customizable drag-and-drop widgets. */
export default function DashboardPage() {
  const [runResult, setRunResult] = useState<RulesRunResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [toasts, setToasts] = useState<{ id: string; title: string; severity: string }[]>([]);

  // HUD displays
  const [systemTime, setSystemTime] = useState(new Date());
  const startTimeRef = useRef(new Date());

  useEffect(() => {
    const t = setInterval(() => setSystemTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const handleWsMessage = useCallback((msg: WsMessage) => {
    if (msg.type === "new_incident") {
      const toast = {
        id: String(Date.now()),
        title: String(msg.payload.title),
        severity: String(msg.payload.severity),
      };
      setToasts((prev) => [toast, ...prev].slice(0, 5));
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== toast.id));
      }, 8000);
    }
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const { connected } = useWebSocket({ onMessage: handleWsMessage });

  const handleAnalyze = useCallback(async () => {
    setRunning(true);
    setRunResult(null);
    setRunError(null);
    try {
      const res = await runRules();
      setRunResult(res);
    } catch (err) {
      setRunError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setRunning(false);
    }
  }, []);

  return (
    <motion.div
      className="space-y-6"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* HUD Header */}
      <motion.div variants={sectionVariants} className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Command Center
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            THREAT MONITORING // REAL-TIME ANALYSIS
          </p>
        </div>

        {/* HUD readouts */}
        <div className="hidden lg:flex items-center gap-6">
          <div className="text-right">
            <p className="hud-label">SYS.TIME</p>
            <p className="font-mono text-sm tabular-nums text-cyan-glow">
              {systemTime.toLocaleTimeString("en-US", { hour12: false })}
            </p>
          </div>
          <div className="h-8 w-px bg-cyan-glow/10" />
          <div className="text-right">
            <p className="hud-label">GRID.REF</p>
            <p className="font-mono text-sm tabular-nums text-cyan-glow/70">
              {(47.2 + Math.sin(Date.now() / 50000) * 0.01).toFixed(4)}N{" "}
              {(2.3 + Math.cos(Date.now() / 50000) * 0.01).toFixed(4)}E
            </p>
          </div>
          <div className="h-8 w-px bg-cyan-glow/10" />
          <div className="text-right">
            <p className="hud-label">UPTIME</p>
            <p className="font-mono text-sm tabular-nums text-cyan-glow/70">
              {formatUptime(systemTime, startTimeRef.current)}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Connection status */}
          <div className="glass-panel flex items-center gap-2 px-3 py-1.5">
            <span className="relative flex h-2 w-2">
              <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${connected ? "animate-ping bg-cyan-glow" : "bg-red-500"}`} />
              <span className={`relative inline-flex h-2 w-2 rounded-full ${connected ? "bg-cyan-glow" : "bg-red-500"}`} />
            </span>
            <span className="text-[10px] tracking-wider text-gray-500">
              {connected ? "LINKED" : "OFFLINE"}
            </span>
          </div>

          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className={`rounded-md px-3 py-2 text-[10px] font-bold tracking-widest transition-all duration-300 ${
              autoRefresh
                ? "border border-cyan-glow/30 bg-cyan-glow/10 text-cyan-glow shadow-cyan-sm"
                : "border border-gray-700 bg-space-mid/50 text-gray-500"
            }`}
          >
            {autoRefresh ? "LIVE" : "PAUSED"}
          </button>

          {/* Analyze button */}
          <button
            onClick={handleAnalyze}
            disabled={running}
            className="group relative overflow-hidden rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-5 py-2.5 text-xs font-bold tracking-wider text-cyan-glow transition-all duration-300 hover:bg-cyan-glow/20 hover:shadow-cyan-md active:scale-95 disabled:opacity-50"
          >
            <div className="pointer-events-none absolute inset-0 bg-gradient-to-r from-transparent via-cyan-glow/10 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
            {running ? (
              <span className="flex items-center gap-2">
                <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                SCANNING...
              </span>
            ) : "ANALYZE"}
          </button>
        </div>
      </motion.div>

      {/* Cyan separator */}
      <div className="cyan-line" />

      {/* Alerts */}
      {(runError) && (
        <motion.div
          variants={sectionVariants}
          className="glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400"
        >
          <span className="mr-2 text-red-500">&#x25B2;</span>
          {runError}
        </motion.div>
      )}

      {runResult && (
        <motion.div
          variants={sectionVariants}
          className="glass-panel border-cyan-glow/30 px-4 py-3 text-xs tracking-wide text-cyan-glow"
        >
          <span className="mr-2">&#x25C6;</span>
          Analysis complete: {runResult.rules_evaluated} rules evaluated,{" "}
          {runResult.incidents_created} incidents created.
        </motion.div>
      )}

      {/* Widget Grid Dashboard */}
      <motion.div variants={sectionVariants}>
        <WidgetGrid registry={WIDGET_REGISTRY} defaultLayout={DEFAULT_LAYOUT} />
      </motion.div>

      {/* Toast Notifications */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className="animate-slide-in glass-panel flex items-start gap-3 border-red-500/30 px-4 py-3 shadow-2xl"
          >
            <div className="mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-red-500/20">
              <svg className="h-3 w-3 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
              </svg>
            </div>
            <div className="flex-1">
              <p className="text-xs font-bold tracking-wider text-red-400">ALERT // NEW INCIDENT</p>
              <p className="text-[10px] text-gray-400">{toast.title}</p>
            </div>
            <button
              onClick={() => dismissToast(toast.id)}
              className="flex-shrink-0 text-gray-600 transition-colors hover:text-cyan-glow"
              aria-label="Dismiss notification"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
