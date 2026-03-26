"use client";

import { Suspense, useCallback, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { listEvents } from "@/lib/apiClient";
import { eventColumns } from "@/lib/columns";
import { DEFAULT_LIMIT, EVENT_SEVERITY_OPTIONS } from "@/lib/constants";
import { readInt, readParam, useFetchData, usePushParams } from "@/lib/hooks";
import { useWebSocket, type WsMessage } from "@/lib/useWebSocket";
import { DataTable } from "@/components/DataTable";
import { FilterBar, FilterInput, FilterSelect } from "@/components/FilterBar";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import { Pagination } from "@/components/Pagination";
import type { Event } from "@/lib/types";

function EventsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pushParams = usePushParams("/events");

  const limit = readInt(searchParams, "limit", DEFAULT_LIMIT);
  const offset = readInt(searchParams, "offset", 0);
  const severity = readParam(searchParams, "severity", "");
  const eventType = readParam(searchParams, "event_type", "");
  const srcIp = readParam(searchParams, "src_ip", "");

  const [refreshKey, setRefreshKey] = useState(0);
  const [liveEvents, setLiveEvents] = useState<Event[]>([]);

  const { data, loading, error } = useFetchData(
    (signal) =>
      listEvents(
        {
          limit,
          offset,
          ...(severity ? { severity } : {}),
          ...(eventType ? { event_type: eventType } : {}),
          ...(srcIp ? { src_ip: srcIp } : {}),
        },
        { signal },
      ),
    [],
    [limit, offset, severity, eventType, srcIp, refreshKey],
  );

  // Real-time WebSocket — new events appear instantly at the top
  const handleWsMessage = useCallback(
    (msg: WsMessage) => {
      if (msg.type !== "new_event") return;
      const p = msg.payload;
      const ev: Event = {
        id: String(p.id ?? ""),
        ts: String(p.ts ?? new Date().toISOString()),
        source: String(p.source ?? ""),
        event_type: String(p.event_type ?? ""),
        severity: (p.severity as Event["severity"]) ?? "low",
        src_ip: p.src_ip ? String(p.src_ip) : null,
        dst_ip: p.dst_ip ? String(p.dst_ip) : null,
        username: p.username ? String(p.username) : null,
        message: p.message ? String(p.message) : null,
        raw: null,
      };

      // Only prepend live if we're on the first page with no filters
      if (offset === 0 && !severity && !eventType && !srcIp) {
        setLiveEvents((prev) => [ev, ...prev].slice(0, 50));
      } else {
        setRefreshKey((k) => k + 1);
      }
    },
    [offset, severity, eventType, srcIp],
  );

  const { connected } = useWebSocket({ onMessage: handleWsMessage });

  // Merge live events (prepended) with fetched data, dedup by id
  const mergedData =
    offset === 0 && !severity && !eventType && !srcIp
      ? [
          ...liveEvents,
          ...data.filter((d) => !liveEvents.some((l) => l.id === d.id)),
        ]
      : data;

  const clearLive = useCallback(() => {
    setLiveEvents([]);
    setRefreshKey((k) => k + 1);
  }, []);

  return (
    <PageTransition className="space-y-4">
      {/* Header */}
      <StaggerItem>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
              Event Journal
            </h1>
            <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
              SECURITY EVENTS // REAL-TIME MONITORING
            </p>
          </div>
          <div className="flex items-center gap-3">
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

            {liveEvents.length > 0 && (
              <button
                onClick={clearLive}
                className="animate-slide-up rounded-md border border-cyan-glow/30 bg-cyan-glow/15 px-3 py-1.5 text-[10px] font-bold tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/25"
              >
                {liveEvents.length} NEW &mdash; SYNC
              </button>
            )}

            <button
              onClick={() => setRefreshKey((k) => k + 1)}
              className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-md active:scale-95"
            >
              REFRESH
            </button>
          </div>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Filters */}
      <StaggerItem>
        <FilterBar
          onReset={() => {
            setLiveEvents([]);
            router.push("/events");
          }}
        >
          <FilterSelect
            label="Severity"
            value={severity}
            options={EVENT_SEVERITY_OPTIONS}
            onChange={(v) => {
              setLiveEvents([]);
              pushParams({ severity: v, offset: 0 });
            }}
          />
          <FilterInput
            label="Event type"
            value={eventType}
            placeholder="e.g. auth.fail"
            onChange={(v) => {
              setLiveEvents([]);
              pushParams({ event_type: v, offset: 0 });
            }}
          />
          <FilterInput
            label="Source IP"
            value={srcIp}
            placeholder="e.g. 10.0.0.1"
            onChange={(v) => {
              setLiveEvents([]);
              pushParams({ src_ip: v, offset: 0 });
            }}
          />
        </FilterBar>
      </StaggerItem>

      {error && (
        <StaggerItem>
          <div className="animate-slide-up glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400">
            <span className="mr-2 text-red-500">&#x25B2;</span>
            {error}
          </div>
        </StaggerItem>
      )}

      {/* Table */}
      <StaggerItem>
        <div className="glass-panel glass-panel-animated overflow-hidden">
          <DataTable
            columns={eventColumns}
            data={mergedData}
            loading={loading}
            error={error}
          />
          {!loading && !error && (
            <div className="px-3 pb-3">
              <Pagination
                offset={offset}
                limit={limit}
                count={data.length}
                onChange={(o) => {
                  setLiveEvents([]);
                  pushParams({ offset: o });
                }}
              />
            </div>
          )}
        </div>
      </StaggerItem>
    </PageTransition>
  );
}

/** Page de consultation des evenements de securite avec filtres et temps reel. */
export default function EventsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex h-40 items-center justify-center">
          <div className="flex flex-col items-center gap-3">
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
            <p className="hud-label animate-pulse">LOADING EVENTS...</p>
          </div>
        </div>
      }
    >
      <EventsContent />
    </Suspense>
  );
}
