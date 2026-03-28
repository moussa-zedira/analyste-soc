"use client";

import { getAttackHeatmap } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import { AttackHeatmap } from "@/components/charts/AttackHeatmap";
import type { HeatmapCell } from "@/lib/types";

export default function HeatmapWidget({ refreshKey }: { refreshKey: number }) {
  const { data: heatmapData, loading } = useFetchData<HeatmapCell[]>(
    (signal) => getAttackHeatmap({ days: 28 }, { signal }),
    [],
    [refreshKey],
  );

  if (loading) {
    return (
      <div className="space-y-2">
        <div className="skeleton h-4 w-48" />
        <div className="skeleton h-[220px] w-full" />
      </div>
    );
  }

  if (heatmapData.length === 0) {
    return (
      <div className="flex h-full min-h-[200px] items-center justify-center">
        <p className="text-[10px] tracking-wider text-gray-600">
          AWAITING HEATMAP DATA...
        </p>
      </div>
    );
  }

  return (
    <div className="h-full min-h-[200px]">
      <AttackHeatmap data={heatmapData} />
    </div>
  );
}
