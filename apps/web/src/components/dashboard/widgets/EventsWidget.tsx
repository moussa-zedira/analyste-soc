"use client";

import { useMemo } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { getEventsPerMinute } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { EventsPerMinuteBucket } from "@/lib/types";

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

export default function EventsWidget({ refreshKey }: { refreshKey: number }) {
  const { data: epmData, loading } = useFetchData<EventsPerMinuteBucket[]>(
    (signal) => getEventsPerMinute({ minutes: 60 }, { signal }),
    [],
    [refreshKey],
  );

  const chartData = useMemo(
    () => epmData.map((d) => ({ time: d.minute.slice(11, 16), count: d.count })),
    [epmData],
  );

  if (loading) {
    return (
      <div className="space-y-2">
        <div className="skeleton h-4 w-40" />
        <div className="skeleton h-[200px] w-full" />
      </div>
    );
  }

  if (chartData.length === 0) {
    return (
      <div className="flex h-full min-h-[200px] items-center justify-center">
        <p className="text-[10px] tracking-wider text-gray-600">
          AWAITING EVENT DATA...
        </p>
      </div>
    );
  }

  return (
    <div className="h-full min-h-[200px]">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 5, right: 5, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id="epmWidgetGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.3} />
              <stop offset="100%" stopColor="#00E5FF" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="time"
            tick={{ fill: "#4A7A8A", fontSize: 9, fontFamily: "JetBrains Mono, monospace" }}
            axisLine={{ stroke: "#006B7D", strokeOpacity: 0.3 }}
            tickLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fill: "#4A7A8A", fontSize: 9, fontFamily: "JetBrains Mono, monospace" }}
            axisLine={false}
            tickLine={false}
            width={30}
          />
          <Tooltip content={<EpmTooltip />} />
          <Area
            type="monotone"
            dataKey="count"
            stroke="#00E5FF"
            strokeWidth={1.5}
            fill="url(#epmWidgetGrad)"
            dot={false}
            activeDot={{ r: 3, fill: "#00E5FF", stroke: "#0B1C2D", strokeWidth: 2 }}
            isAnimationActive={true}
            animationDuration={800}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
