"use client";

import { getKpis } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { KpiResponse } from "@/lib/types";

const kpiItems = [
  { key: "total_events_24h" as const, label: "EVENTS 24H", accent: "glow-text" },
  { key: "open_incidents" as const, label: "OPEN INCIDENTS", accent: "text-red-400" },
  { key: "high_incidents_24h" as const, label: "HIGH SEV 24H", accent: "text-orange-400" },
];

export default function KPIWidget({ refreshKey }: { refreshKey: number }) {
  const { data: kpis, loading } = useFetchData<KpiResponse | null>(
    (signal) => getKpis({ signal }),
    null,
    [refreshKey],
  );

  if (loading) {
    return (
      <div className="grid grid-cols-3 gap-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="rounded-md border border-cyan-glow/10 bg-space-mid/50 p-3">
            <div className="skeleton h-3 w-16 mb-2" />
            <div className="skeleton h-7 w-12" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-3 gap-3">
      {kpiItems.map(({ key, label, accent }) => (
        <div
          key={key}
          className="rounded-md border border-cyan-glow/10 bg-space-mid/30 p-3 transition-all hover:border-cyan-glow/25 hover:bg-space-mid/50"
        >
          <p className="text-[8px] font-bold tracking-widest text-gray-500 mb-1">{label}</p>
          <p className={`text-2xl font-bold tabular-nums ${accent}`}>
            {kpis?.[key] ?? 0}
          </p>
        </div>
      ))}
    </div>
  );
}
