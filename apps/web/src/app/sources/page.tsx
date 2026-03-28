"use client";

import { useCallback, useEffect, useState } from "react";
import { getLogSources } from "@/lib/apiClient";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import type { LogSourceStatus } from "@/lib/types";

export default function SourcesPage() {
  const [sources, setSources] = useState<LogSourceStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getLogSources();
      setSources(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30_000);
    return () => clearInterval(interval);
  }, [load]);

  const totalEvents = sources.reduce((s, src) => s + src.event_count, 0);
  const totalRate = sources.reduce((s, src) => s + src.events_per_minute, 0);

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
              Log Sources
            </h1>
            <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
              COLLECTEURS // SOURCES DE DONNEES ACTIVES
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] text-gray-500 font-mono">
              {sources.length} sources / {totalEvents} events
            </span>
            <button
              onClick={load}
              className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-3 py-1.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors"
            >
              REFRESH
            </button>
          </div>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* KPI row */}
      <StaggerItem>
        <div className="grid grid-cols-3 gap-4">
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">{sources.length}</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">SOURCES ACTIVES</p>
          </div>
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">{totalEvents.toLocaleString()}</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">EVENTS TOTAL</p>
          </div>
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">{totalRate.toFixed(1)}</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">EVENTS / MIN</p>
          </div>
        </div>
      </StaggerItem>

      {error && (
        <StaggerItem>
          <div className="glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400">
            <span className="mr-2 text-red-500">&#x25B2;</span>{error}
          </div>
        </StaggerItem>
      )}

      {loading ? (
        <StaggerItem>
          <div className="flex h-40 items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <div className="relative h-10 w-10">
                <div className="absolute inset-0 rounded-full border-2 border-cyan-glow/20 animate-ping" />
                <div className="absolute inset-2 rounded-full border-2 border-t-cyan-glow border-transparent animate-spin" />
              </div>
              <p className="hud-label animate-pulse">LOADING SOURCES...</p>
            </div>
          </div>
        </StaggerItem>
      ) : sources.length === 0 ? (
        <StaggerItem>
          <div className="glass-panel p-8 text-center">
            <p className="text-sm text-gray-400">Aucune source de logs detectee</p>
            <p className="text-[10px] text-gray-600 mt-2 max-w-md mx-auto">
              Configurez un collecteur (syslog, Windows Event Log ou file watcher)
              pour commencer a recevoir des evenements.
            </p>
          </div>
        </StaggerItem>
      ) : (
        <StaggerItem>
          <div className="glass-panel overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">SOURCE</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500 text-right">EVENTS</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500 text-right">EVT/MIN</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500 text-right">DERNIER</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">STATUT</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((src) => {
                  const isActive = src.events_per_minute > 0;
                  const lastSeen = src.last_seen ? new Date(src.last_seen) : null;
                  const minutesAgo = lastSeen
                    ? Math.round((Date.now() - lastSeen.getTime()) / 60000)
                    : null;
                  const isRecent = minutesAgo !== null && minutesAgo < 10;

                  return (
                    <tr
                      key={src.source}
                      className="border-b border-gray-800/50 hover:bg-cyan-glow/5 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className={`inline-block h-2 w-2 rounded-full ${isRecent ? "bg-green-500" : "bg-gray-600"}`} />
                          <span className="text-sm font-mono text-gray-300">{src.source}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right text-sm font-mono text-cyan-glow">
                        {src.event_count.toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right text-sm font-mono text-gray-400">
                        {src.events_per_minute.toFixed(1)}
                      </td>
                      <td className="px-4 py-3 text-right text-[11px] text-gray-500">
                        {minutesAgo !== null
                          ? minutesAgo < 1
                            ? "< 1 min"
                            : `${minutesAgo} min`
                          : "—"
                        }
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`rounded-full px-2 py-0.5 text-[10px] font-bold tracking-wider ${
                            isActive
                              ? "bg-green-500/15 text-green-400 border border-green-500/30"
                              : isRecent
                                ? "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30"
                                : "bg-gray-700/50 text-gray-500 border border-gray-600/30"
                          }`}
                        >
                          {isActive ? "ACTIF" : isRecent ? "IDLE" : "INACTIF"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </StaggerItem>
      )}

      {/* Setup instructions */}
      <StaggerItem>
        <div className="glass-panel p-4 space-y-3">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500">CONFIGURATION DES COLLECTEURS</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="rounded-lg border border-cyan-glow/10 p-3">
              <p className="text-xs font-bold text-cyan-glow mb-1">Syslog (UDP/TCP)</p>
              <p className="text-[10px] text-gray-500 font-mono">
                Port UDP 514 / TCP 1514<br />
                Compatible RFC 3164 & 5424
              </p>
            </div>
            <div className="rounded-lg border border-cyan-glow/10 p-3">
              <p className="text-xs font-bold text-cyan-glow mb-1">Windows Event Log</p>
              <p className="text-[10px] text-gray-500 font-mono">
                python -m apps.collectors winlog<br />
                Security, System, Application
              </p>
            </div>
            <div className="rounded-lg border border-cyan-glow/10 p-3">
              <p className="text-xs font-bold text-cyan-glow mb-1">File Watcher</p>
              <p className="text-[10px] text-gray-500 font-mono">
                python -m apps.collectors filewatcher<br />
                /var/log/auth.log /var/log/syslog
              </p>
            </div>
          </div>
        </div>
      </StaggerItem>
    </PageTransition>
  );
}
