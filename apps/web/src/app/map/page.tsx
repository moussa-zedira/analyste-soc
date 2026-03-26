"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { DynamicThreatMap } from "@/components/map/DynamicThreatMap";
import { getGeoEvents } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import { useWebSocket, type WsMessage } from "@/lib/useWebSocket";
import type { GeoEvent } from "@/lib/types";

export default function MapPage() {
  const [refreshKey, setRefreshKey] = useState(0);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data, loading, error } = useFetchData<GeoEvent[]>(
    (signal) => getGeoEvents({ limit: 200 }, { signal }),
    [],
    [refreshKey],
  );

  // Real-time: debounced auto-refresh when new events arrive via WebSocket
  const handleWsMessage = useCallback((msg: WsMessage) => {
    if (msg.type === "new_event" || msg.type === "new_incident") {
      // Debounce to avoid excessive re-fetches when many events arrive at once
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        setRefreshKey((k) => k + 1);
      }, 1000);
    }
  }, []);

  useEffect(() => {
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, []);

  const { connected } = useWebSocket({ onMessage: handleWsMessage });

  const totalEvents = data.reduce((sum, g) => sum + g.event_count, 0);
  const uniqueCountries = new Set(data.map((g) => g.country)).size;
  const criticalCount = data.filter(
    (g) => g.max_severity === "critical" || g.max_severity === "high",
  ).length;

  return (
    <div className="space-y-4 animate-hud-reveal">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Threat Map
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            GLOBAL THREAT DISTRIBUTION // GEO-INTELLIGENCE
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Stats badges */}
          <div className="hidden md:flex items-center gap-3">
            <div className="glass-panel px-3 py-1.5 text-center">
              <p className="text-[9px] tracking-wider text-cyan-glow/40">
                SOURCES
              </p>
              <p className="font-mono text-sm font-bold text-cyan-glow">
                {data.length}
              </p>
            </div>
            <div className="glass-panel px-3 py-1.5 text-center">
              <p className="text-[9px] tracking-wider text-cyan-glow/40">
                EVENTS
              </p>
              <p className="font-mono text-sm font-bold text-cyan-glow">
                {totalEvents}
              </p>
            </div>
            <div className="glass-panel px-3 py-1.5 text-center">
              <p className="text-[9px] tracking-wider text-cyan-glow/40">
                COUNTRIES
              </p>
              <p className="font-mono text-sm font-bold text-cyan-glow">
                {uniqueCountries}
              </p>
            </div>
            <div className="glass-panel px-3 py-1.5 text-center">
              <p className="text-[9px] tracking-wider text-red-400/50">
                HIGH/CRIT
              </p>
              <p className="font-mono text-sm font-bold text-red-400">
                {criticalCount}
              </p>
            </div>
          </div>

          {/* Connection status */}
          <div className="glass-panel flex items-center gap-2 px-3 py-1.5">
            <span className="relative flex h-2 w-2">
              <span
                className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  connected ? "animate-ping bg-cyan-glow" : "bg-red-500"
                }`}
              />
              <span
                className={`relative inline-flex h-2 w-2 rounded-full ${
                  connected ? "bg-cyan-glow" : "bg-red-500"
                }`}
              />
            </span>
            <span className="text-[10px] tracking-wider text-gray-500">
              {connected ? "LIVE" : "OFFLINE"}
            </span>
          </div>

          <button
            onClick={() => setRefreshKey((k) => k + 1)}
            className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-md active:scale-95"
          >
            REFRESH
          </button>
        </div>
      </div>

      <div className="cyan-line" />

      {error && (
        <div className="animate-slide-up glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400">
          <span className="mr-2 text-red-500">&#x25B2;</span>
          {error}
        </div>
      )}

      {/* Map container */}
      <div
        className="glass-panel glass-panel-animated overflow-hidden p-1"
        style={{ height: "calc(100vh - 220px)" }}
      >
        {loading && data.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3">
            <svg
              className="h-8 w-8 animate-spin text-cyan-glow/50"
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
            <p className="hud-label animate-pulse">LOADING GEO DATA...</p>
          </div>
        ) : (
          <DynamicThreatMap data={data} />
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center justify-center gap-6">
        {[
          { label: "LOW", color: "#00E5FF" },
          { label: "MEDIUM", color: "#EAB308" },
          { label: "HIGH", color: "#F97316" },
          { label: "CRITICAL", color: "#EF4444" },
        ].map(({ label, color }) => (
          <div key={label} className="flex items-center gap-2">
            <div
              className="h-2.5 w-2.5 rounded-full"
              style={{
                backgroundColor: color,
                boxShadow: `0 0 8px ${color}60`,
              }}
            />
            <span className="text-[10px] tracking-wider text-gray-500">
              {label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
