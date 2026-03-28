"use client";

import { listIncidents } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { Incident } from "@/lib/types";

const severityColors: Record<string, string> = {
  low: "border-cyan-glow/30 text-cyan-glow bg-cyan-glow/10",
  medium: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  high: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  critical: "border-red-500/30 text-red-400 bg-red-500/10",
};

const statusIcons: Record<string, string> = {
  open: "text-red-400",
  ack: "text-yellow-400",
  closed: "text-green-400",
};

export default function IncidentsWidget({ refreshKey }: { refreshKey: number }) {
  const { data: incidents, loading } = useFetchData<Incident[]>(
    (signal) => listIncidents({ limit: 10, status_filter: "open" }, { signal }),
    [],
    [refreshKey],
  );

  if (loading) {
    return (
      <div className="space-y-2">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="skeleton h-10 w-full" />
        ))}
      </div>
    );
  }

  if (incidents.length === 0) {
    return (
      <div className="flex h-full min-h-[120px] items-center justify-center">
        <div className="text-center">
          <p className="text-[10px] tracking-wider text-gray-600">NO OPEN INCIDENTS</p>
          <p className="mt-1 text-[8px] tracking-wider text-gray-700">ALL CLEAR</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-h-[300px] space-y-1.5 overflow-y-auto">
      {incidents.map((inc) => (
        <div
          key={inc.id}
          className="flex items-center gap-2 rounded-md px-2.5 py-2 transition-colors hover:bg-cyan-glow/5"
        >
          {/* Status dot */}
          <span className={`h-1.5 w-1.5 rounded-full ${statusIcons[inc.status] ?? "text-gray-500"}`}
            style={{ backgroundColor: "currentColor" }}
          />

          {/* Severity badge */}
          <span className={`rounded border px-1.5 py-0.5 text-[8px] font-bold tracking-wider ${severityColors[inc.severity] ?? severityColors.low}`}>
            {inc.severity.toUpperCase()}
          </span>

          {/* Title */}
          <span className="flex-1 truncate text-[11px] text-gray-300">
            {inc.title}
          </span>

          {/* Time */}
          <span className="shrink-0 text-[9px] font-mono text-cyan-glow/30">
            {inc.created_at?.slice(11, 16) ?? ""}
          </span>
        </div>
      ))}
    </div>
  );
}
