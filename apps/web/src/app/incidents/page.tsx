"use client";

import { Suspense, useCallback, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { listIncidents } from "@/lib/apiClient";
import { DEFAULT_LIMIT, SEVERITY_OPTIONS, STATUS_OPTIONS } from "@/lib/constants";
import { readInt, readParam, useFetchData, usePushParams } from "@/lib/hooks";
import { useWebSocket, type WsMessage } from "@/lib/useWebSocket";
import type { Incident } from "@/lib/types";
import { SeverityBadge, StatusBadge } from "@/components/Badge";
import { DataTable, type Column } from "@/components/DataTable";
import { FilterBar, FilterSelect } from "@/components/FilterBar";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import { Pagination } from "@/components/Pagination";
import { HudHeading, HudCard, HudButton } from "@/components/hud";

const columns: Column<Incident>[] = [
  {
    header: "Created",
    accessor: (r) => (
      <span className="whitespace-nowrap font-mono text-xs text-cyan-glow/60">
        {new Date(r.created_at).toLocaleString()}
      </span>
    ),
  },
  {
    header: "Status",
    accessor: (r) => <StatusBadge value={r.status} />,
  },
  {
    header: "Severity",
    accessor: (r) => <SeverityBadge value={r.severity} />,
  },
  {
    header: "Title",
    accessor: (r) => (
      <span className="block max-w-sm truncate font-medium text-gray-200">
        {r.title}
      </span>
    ),
  },
  {
    header: "Rule",
    accessor: (r) => (
      <span className="font-mono text-cyan-dim/70">{r.rule_id}</span>
    ),
  },
  {
    header: "Entity",
    accessor: (r) => (
      <span className="font-mono text-cyan-glow/50">{r.entity_key}</span>
    ),
  },
];

function IncidentsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pushParams = usePushParams("/incidents");

  const limit = readInt(searchParams, "limit", DEFAULT_LIMIT);
  const offset = readInt(searchParams, "offset", 0);
  const severity = readParam(searchParams, "severity", "");
  const statusFilter = readParam(searchParams, "status_filter", "");
  const [refreshKey, setRefreshKey] = useState(0);

  // Real-time: auto-refresh when new incidents arrive
  const handleWsMessage = useCallback((msg: WsMessage) => {
    if (msg.type === "new_incident") {
      setRefreshKey((k) => k + 1);
    }
  }, []);

  const { connected } = useWebSocket({ onMessage: handleWsMessage });

  const { data, loading, error } = useFetchData(
    (signal) =>
      listIncidents(
        {
          limit,
          offset,
          ...(severity ? { severity } : {}),
          ...(statusFilter ? { status_filter: statusFilter } : {}),
        },
        { signal },
      ),
    [],
    [limit, offset, severity, statusFilter, refreshKey],
  );

  return (
    <PageTransition className="space-y-4">
      {/* Header */}
      <StaggerItem>
        <div className="flex items-center justify-between">
          <HudHeading level={1} subtitle="SECURITY INCIDENTS // THREAT MANAGEMENT">
            Incidents
          </HudHeading>
          <div className="flex items-center gap-3">
            <HudCard className="flex items-center gap-2 px-3 py-1.5">
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
            </HudCard>
            <HudButton variant="primary" size="sm" onClick={() => setRefreshKey((k) => k + 1)}>
              REFRESH
            </HudButton>
          </div>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      <StaggerItem>
        <FilterBar onReset={() => router.push("/incidents")}>
          <FilterSelect
            label="Severity"
            value={severity}
            options={SEVERITY_OPTIONS}
            onChange={(v) => pushParams({ severity: v, offset: 0 })}
          />
          <FilterSelect
            label="Status"
            value={statusFilter}
            options={STATUS_OPTIONS}
            onChange={(v) => pushParams({ status_filter: v, offset: 0 })}
          />
        </FilterBar>
      </StaggerItem>

      {error && (
        <StaggerItem>
          <HudCard tone="alert" className="animate-slide-up px-4 py-3 text-xs tracking-wide text-neon-pink">
            <span className="mr-2 text-neon-pink">&#x25B2;</span>
            {error}
          </HudCard>
        </StaggerItem>
      )}

      <StaggerItem>
        <HudCard className="glass-panel-animated overflow-hidden p-0">
          <DataTable
            columns={columns}
            data={data}
            loading={loading}
            error={error}
            onRowClick={(row) => router.push(`/incidents/${row.id}`)}
          />
          {!loading && !error && (
            <div className="px-3 pb-3">
              <Pagination
                offset={offset}
                limit={limit}
                count={data.length}
                onChange={(o) => pushParams({ offset: o })}
              />
            </div>
          )}
        </HudCard>
      </StaggerItem>
    </PageTransition>
  );
}

/** Page de liste des incidents avec filtres par severite et statut. */
export default function IncidentsPage() {
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
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <p className="hud-label animate-pulse">LOADING INCIDENTS...</p>
          </div>
        </div>
      }
    >
      <IncidentsContent />
    </Suspense>
  );
}
