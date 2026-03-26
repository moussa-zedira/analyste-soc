"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { AttackHeatmap } from "@/components/charts/AttackHeatmap";
import {
  getKpis,
  runRules,
  getEventsPerMinute,
  getAttackHeatmap,
} from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import { useWebSocket, type WsMessage } from "@/lib/useWebSocket";
import { SeverityBadge } from "@/components/Badge";
import { ThreatScoresCard } from "@/components/ThreatScoresCard";
import { MLStatusCard } from "@/components/MLStatusCard";
import type {
  KpiResponse,
  RulesRunResponse,
  EventsPerMinuteBucket,
  HeatmapCell,
} from "@/lib/types";

const AUTO_REFRESH_INTERVAL = 10_000;

/** Couleurs de severite pour le donut chart */
const SEVERITY_COLORS: Record<string, string> = {
  low: "#00E5FF",
  medium: "#EAB308",
  high: "#F97316",
  critical: "#EF4444",
};

/* ── Variants d'animation framer-motion ── */
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

/* ── Effet de texte "scan-in" pour le dernier evenement ── */
function ScanInText({
  text,
  duration = 400,
}: {
  text: string;
  duration?: number;
}) {
  const [visibleChars, setVisibleChars] = useState(0);

  useEffect(() => {
    setVisibleChars(0);
    if (!text) return;
    const charDelay = duration / text.length;
    let i = 0;
    const interval = setInterval(() => {
      i++;
      setVisibleChars(i);
      if (i >= text.length) clearInterval(interval);
    }, charDelay);
    return () => clearInterval(interval);
  }, [text, duration]);

  return (
    <span>
      <span>{text.slice(0, visibleChars)}</span>
      <span className="opacity-0">{text.slice(visibleChars)}</span>
      {visibleChars < text.length && (
        <span className="ml-0.5 inline-block h-3 w-1.5 animate-pulse bg-cyan-glow" />
      )}
    </span>
  );
}

/* ── Formateur d'uptime ── */
function formatUptime(now: Date, start: Date): string {
  const diff = Math.floor((now.getTime() - start.getTime()) / 1000);
  const h = Math.floor(diff / 3600)
    .toString()
    .padStart(2, "0");
  const m = Math.floor((diff % 3600) / 60)
    .toString()
    .padStart(2, "0");
  const s = (diff % 60).toString().padStart(2, "0");
  return `${h}:${m}:${s}`;
}

/* ── Tooltip personnalise style glass-panel pour le graphique ── */
function EpmTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="rounded-lg border border-cyan-500/20 px-3 py-2 text-xs shadow-xl backdrop-blur-md"
      style={{ background: "rgba(11, 28, 45, 0.95)" }}
    >
      <p className="font-semibold text-cyan-300">{payload[0].value} events</p>
      <p className="text-gray-500">{label}</p>
    </div>
  );
}

/** Page principale du tableau de bord — Command Center avec KPIs, graphiques et flux temps reel. */
export default function DashboardPage() {
  const [refreshKey, setRefreshKey] = useState(0);
  const [runResult, setRunResult] = useState<RulesRunResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [liveEvents, setLiveEvents] = useState<WsMessage["payload"][]>([]);
  const [toasts, setToasts] = useState<
    { id: string; title: string; severity: string }[]
  >([]);

  // Affichage HUD
  const [systemTime, setSystemTime] = useState(new Date());
  const startTimeRef = useRef(new Date());
  const [meters, setMeters] = useState({ cpu: 52, mem: 61, net: 34 });

  // Compteur de generation du flux pour re-declencher les animations de stagger
  const feedGenRef = useRef(0);
  const prevLenRef = useRef(0);

  useEffect(() => {
    const t = setInterval(() => setSystemTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  // Valeurs des jauges systeme qui derivent lentement
  useEffect(() => {
    const t = setInterval(() => {
      setMeters((prev) => ({
        cpu: Math.min(95, Math.max(25, prev.cpu + (Math.random() * 10 - 5))),
        mem: Math.min(90, Math.max(30, prev.mem + (Math.random() * 6 - 3))),
        net: Math.min(85, Math.max(10, prev.net + (Math.random() * 12 - 6))),
      }));
    }, 3000);
    return () => clearInterval(t);
  }, []);

  const handleWsMessage = useCallback((msg: WsMessage) => {
    if (msg.type === "new_event") {
      setLiveEvents((prev) => [msg.payload, ...prev].slice(0, 50));
    }
    if (msg.type === "new_incident") {
      setRefreshKey((k) => k + 1);
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

  const {
    data: kpis,
    loading,
    error,
  } = useFetchData(
    (signal) => getKpis({ signal }),
    null as KpiResponse | null,
    [refreshKey],
  );

  const { data: epmData } = useFetchData<EventsPerMinuteBucket[]>(
    (signal) => getEventsPerMinute({ minutes: 60 }, { signal }),
    [],
    [refreshKey],
  );

  const { data: heatmapData } = useFetchData<HeatmapCell[]>(
    (signal) => getAttackHeatmap({ days: 28 }, { signal }),
    [],
    [refreshKey],
  );

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(() => {
        setRefreshKey((k) => k + 1);
      }, AUTO_REFRESH_INTERVAL);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [autoRefresh]);

  const handleAnalyze = useCallback(async () => {
    setRunning(true);
    setRunResult(null);
    setRunError(null);
    try {
      const res = await runRules();
      setRunResult(res);
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setRunError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setRunning(false);
    }
  }, []);

  // Suivi de la generation du flux pour l'animation stagger
  if (liveEvents.length !== prevLenRef.current) {
    feedGenRef.current++;
    prevLenRef.current = liveEvents.length;
  }

  /* ── Donnees formatees pour le graphique Events Per Minute (Recharts) ── */
  const epmChartData = useMemo(
    () =>
      epmData.map((d) => ({
        time: d.minute.slice(11, 16), // HH:MM
        count: d.count,
      })),
    [epmData],
  );

  /* ── Donnees de distribution de severite derivees des evenements live ── */
  const severityData = useMemo(() => {
    // Compter les severites a partir des evenements en direct
    const counts: Record<string, number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    liveEvents.forEach((ev) => {
      const sev = String(ev.severity ?? "low").toLowerCase();
      if (sev in counts) counts[sev]++;
    });

    // Ajouter les donnees KPI pour enrichir les compteurs
    if (kpis) {
      counts.high += kpis.high_incidents_24h;
      // Estimer les autres niveaux a partir des evenements totaux
      const remaining = Math.max(
        0,
        kpis.total_events_24h -
          kpis.high_incidents_24h -
          counts.low -
          counts.medium -
          counts.critical,
      );
      counts.low += Math.round(remaining * 0.5);
      counts.medium += Math.round(remaining * 0.35);
      counts.critical += Math.round(remaining * 0.15);
    }

    return Object.entries(counts)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
        color: SEVERITY_COLORS[name],
      }));
  }, [liveEvents, kpis]);

  /* ── Sparklines synthetiques pour les cartes KPI ── */
  const eventsSparkData = useMemo(
    () => epmData.slice(-20).map((d) => d.count),
    [epmData],
  );

  return (
    <motion.div
      className="space-y-6"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* ═══ En-tete HUD ═══ */}
      <motion.div
        variants={sectionVariants}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Command Center
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            THREAT MONITORING // REAL-TIME ANALYSIS
          </p>
        </div>

        {/* Lectures HUD (bureau uniquement) */}
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
          {/* Statut de connexion */}
          <div className="glass-panel flex items-center gap-2 px-3 py-1.5">
            <span className="relative flex h-2 w-2">
              <span
                className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  connected
                    ? "animate-ping bg-cyan-glow"
                    : "bg-red-500"
                }`}
              />
              <span
                className={`relative inline-flex h-2 w-2 rounded-full ${
                  connected ? "bg-cyan-glow" : "bg-red-500"
                }`}
              />
            </span>
            <span className="text-[10px] tracking-wider text-gray-500">
              {connected ? "LINKED" : "OFFLINE"}
            </span>
          </div>

          {/* Bascule auto-refresh */}
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

          {/* Bouton d'analyse */}
          <button
            onClick={handleAnalyze}
            disabled={running}
            className="group relative overflow-hidden rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-5 py-2.5 text-xs font-bold tracking-wider text-cyan-glow transition-all duration-300 hover:bg-cyan-glow/20 hover:shadow-cyan-md active:scale-95 disabled:opacity-50"
          >
            <div className="pointer-events-none absolute inset-0 bg-gradient-to-r from-transparent via-cyan-glow/10 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
            {running ? (
              <span className="flex items-center gap-2">
                <svg
                  className="h-4 w-4 animate-spin"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                  />
                </svg>
                SCANNING...
              </span>
            ) : (
              "ANALYZE"
            )}
          </button>
        </div>
      </motion.div>

      {/* Ligne de separation cyan */}
      <div className="cyan-line" />

      {/* ═══ Jauges systeme ═══ */}
      <motion.div variants={sectionVariants} className="grid grid-cols-3 gap-4">
        {[
          { label: "CPU LOAD", value: meters.cpu },
          { label: "MEMORY", value: meters.mem },
          { label: "NETWORK", value: meters.net },
        ].map(({ label, value }) => (
          <div key={label}>
            <div className="mb-1 flex justify-between">
              <span className="hud-label">{label}</span>
              <span className="text-[10px] tabular-nums text-cyan-glow/50">
                {Math.round(value)}%
              </span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-space-mid">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-glow/60 to-cyan-glow transition-all duration-1000"
                style={{ width: `${value}%` }}
              />
            </div>
          </div>
        ))}
      </motion.div>

      {/* Alertes */}
      {(error || runError) && (
        <motion.div
          variants={sectionVariants}
          className="glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400"
        >
          <span className="mr-2 text-red-500">&#x25B2;</span>
          {error || runError}
        </motion.div>
      )}

      {runResult && (
        <motion.div
          variants={sectionVariants}
          className="glass-panel border-cyan-glow/30 px-4 py-3 text-xs tracking-wide text-cyan-glow"
        >
          <span className="mr-2">&#x25C6;</span>
          Analyse terminee : {runResult.rules_evaluated} regles evaluees,{" "}
          {runResult.incidents_created} incidents crees.
        </motion.div>
      )}

      {/* ═══ Cartes KPI + Donut Severite ═══ */}
      <motion.div
        variants={sectionVariants}
        className="grid grid-cols-1 gap-4 xl:grid-cols-4"
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 xl:col-span-3">
          <Card
            title="Events (24h)"
            value={kpis?.total_events_24h ?? 0}
            subtitle="Security events in last 24 hours"
            accent="glow-text"
            loading={loading}
            sparkData={eventsSparkData.length > 2 ? eventsSparkData : undefined}
          />
          <Card
            title="Open Incidents"
            value={kpis?.open_incidents ?? 0}
            subtitle="Incidents requiring attention"
            accent="text-red-400"
            loading={loading}
          />
          <Card
            title="High Severity"
            value={kpis?.high_incidents_24h ?? 0}
            subtitle="High severity incidents (24h)"
            accent="text-orange-400"
            loading={loading}
          />
        </div>

        {/* Donut de distribution de severite */}
        <div className="glass-panel glass-panel-animated flex flex-col items-center justify-center p-4">
          <p className="hud-label mb-2">Severity Distribution</p>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  dataKey="value"
                  stroke="none"
                  animationBegin={200}
                  animationDuration={800}
                >
                  {severityData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.color} fillOpacity={0.85} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div
                        className="rounded-lg border border-cyan-500/20 px-3 py-2 text-xs shadow-xl backdrop-blur-md"
                        style={{ background: "rgba(11, 28, 45, 0.95)" }}
                      >
                        <p style={{ color: d.color }} className="font-semibold">
                          {d.name}
                        </p>
                        <p className="text-gray-400">{d.value} events</p>
                      </div>
                    );
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[180px] items-center justify-center">
              <p className="text-[10px] tracking-wider text-gray-600">
                EN ATTENTE DE DONNEES...
              </p>
            </div>
          )}
          {/* Legende compacte */}
          <div className="mt-1 flex flex-wrap justify-center gap-x-3 gap-y-1">
            {severityData.map((s) => (
              <div key={s.name} className="flex items-center gap-1">
                <span
                  className="inline-block h-2 w-2 rounded-full"
                  style={{ backgroundColor: s.color }}
                />
                <span className="text-[9px] tracking-wider text-gray-500">
                  {s.name}
                </span>
              </div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* ═══ Graphiques ═══ */}
      <motion.div
        variants={sectionVariants}
        className="grid grid-cols-1 gap-4 xl:grid-cols-2"
      >
        {/* Events par minute — Recharts AreaChart */}
        <div className="glass-panel glass-panel-animated scan-overlay p-5">
          <h2 className="hud-label mb-4">
            Events par minute (derniere heure)
          </h2>
          {epmChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart
                data={epmChartData}
                margin={{ top: 10, right: 10, bottom: 0, left: 0 }}
              >
                <defs>
                  <linearGradient id="epmGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#00E5FF" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="time"
                  tick={{ fill: "#4A7A8A", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }}
                  axisLine={{ stroke: "#006B7D", strokeOpacity: 0.3 }}
                  tickLine={{ stroke: "#006B7D", strokeOpacity: 0.2 }}
                  interval="preserveStartEnd"
                />
                <YAxis
                  tick={{ fill: "#4A7A8A", fontSize: 10, fontFamily: "JetBrains Mono, monospace" }}
                  axisLine={{ stroke: "#006B7D", strokeOpacity: 0.3 }}
                  tickLine={{ stroke: "#006B7D", strokeOpacity: 0.2 }}
                  width={40}
                />
                <Tooltip content={<EpmTooltip />} />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#00E5FF"
                  strokeWidth={2}
                  fill="url(#epmGradient)"
                  dot={false}
                  activeDot={{
                    r: 4,
                    fill: "#00E5FF",
                    stroke: "#0B1C2D",
                    strokeWidth: 2,
                  }}
                  isAnimationActive={true}
                  animationDuration={800}
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState
              icon="chart"
              title="Aucune donnee disponible"
              description="Les donnees apparaitront ici une fois des events ingeres"
            />
          )}
        </div>

        {/* Heatmap des attaques */}
        <div className="glass-panel glass-panel-animated scan-overlay p-5">
          <h2 className="hud-label mb-4">
            Heatmap des attaques (4 semaines)
          </h2>
          {heatmapData.length > 0 ? (
            <AttackHeatmap data={heatmapData} />
          ) : (
            <EmptyState
              icon="chart"
              title="Aucune donnee disponible"
              description="Les donnees apparaitront ici une fois des events ingeres"
            />
          )}
        </div>
      </motion.div>

      {/* ═══ ML & Threat Scores ═══ */}
      <motion.div
        variants={sectionVariants}
        className="grid grid-cols-1 gap-4 xl:grid-cols-2"
      >
        <MLStatusCard onDetection={() => setRefreshKey((k) => k + 1)} />
        <ThreatScoresCard refreshKey={refreshKey} />
      </motion.div>

      {/* ═══ Flux d'evenements en direct ═══ */}
      <motion.div variants={sectionVariants} className="glass-panel p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="hud-label">Live Event Feed</h2>
          {liveEvents.length > 0 && (
            <span className="rounded-full border border-cyan-glow/20 bg-cyan-glow/10 px-2.5 py-0.5 text-[10px] font-medium tracking-wider text-cyan-glow">
              {liveEvents.length} EVENTS
            </span>
          )}
        </div>
        {liveEvents.length === 0 ? (
          <EmptyState
            icon="inbox"
            title="En attente d'evenements..."
            description="Les events en temps reel apparaitront ici via WebSocket"
          />
        ) : (
          <div className="max-h-72 overflow-y-auto space-y-0.5">
            {liveEvents.map((ev, i) => (
              <div
                key={`${feedGenRef.current}-${i}`}
                className="flex items-center gap-3 rounded-md px-3 py-2 text-xs transition-colors hover:bg-cyan-glow/5"
                style={{
                  animation:
                    i < 5
                      ? `slide-up 0.35s ease-out ${i * 0.06}s both`
                      : "none",
                }}
              >
                <span className="font-mono text-[10px] text-cyan-glow/40">
                  {String(ev.ts ?? "").slice(11, 19)}
                </span>
                <SeverityBadge value={String(ev.severity ?? "")} />
                <span className="font-medium text-gray-300">
                  {String(ev.event_type ?? "")}
                </span>
                <span className="font-mono text-cyan-dim/50">
                  {String(ev.src_ip ?? "")}
                </span>
                <span className="flex-1 truncate text-gray-500">
                  {i === 0 ? (
                    <ScanInText text={String(ev.message ?? "")} />
                  ) : (
                    String(ev.message ?? "")
                  )}
                </span>
              </div>
            ))}
          </div>
        )}
      </motion.div>

      {/* ═══ Notifications toast ═══ */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className="animate-slide-in glass-panel flex items-start gap-3 border-red-500/30 px-4 py-3 shadow-2xl"
          >
            <div className="mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-red-500/20">
              <svg
                className="h-3 w-3 text-red-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z"
                />
              </svg>
            </div>
            <div className="flex-1">
              <p className="text-xs font-bold tracking-wider text-red-400">
                ALERT // NEW INCIDENT
              </p>
              <p className="text-[10px] text-gray-400">{toast.title}</p>
            </div>
            <button
              onClick={() => dismissToast(toast.id)}
              className="flex-shrink-0 text-gray-600 transition-colors hover:text-cyan-glow"
              aria-label="Dismiss notification"
            >
              <svg
                className="h-4 w-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
