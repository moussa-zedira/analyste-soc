"use client";

/**
 * Graphique en aire affichant le nombre d'evenements par minute.
 * Utilise Recharts avec un remplissage degrade cyan et une courbe lissee.
 */

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";
import type { EventsPerMinuteBucket } from "@/lib/types";

interface Props {
  /** Donnees : un tableau de buckets minute / count */
  data: EventsPerMinuteBucket[];
  /** Largeur optionnelle (ignoree car ResponsiveContainer gere la largeur) */
  width?: number;
  /** Hauteur du graphique en pixels */
  height?: number;
}

const CYAN = "#00E5FF";
const GRID_STROKE = "#0F2A40";
const LABEL_COLOR = "#4A7A8A";

/**
 * Formate un timestamp ISO en HH:MM.
 */
function formatTime(minute: string): string {
  const d = new Date(minute);
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

/**
 * Infobulle personnalisee avec style glass-panel.
 */
function CyanTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ value: number }>;
  label?: string;
}) {
  if (!active || !payload?.length || !label) return null;

  return (
    <div
      className="pointer-events-none rounded-md border border-cyan-500/20 bg-space-dark/95 px-3 py-2 shadow-xl backdrop-blur-sm"
      style={{ fontFamily: "JetBrains Mono, monospace" }}
    >
      <div className="text-xs font-semibold" style={{ color: CYAN }}>
        {payload[0].value} events
      </div>
      <div className="text-xs" style={{ color: LABEL_COLOR }}>
        {formatTime(label)}
      </div>
    </div>
  );
}

/** Composant principal : courbe d'evenements par minute */
export function EventsPerMinuteChart({
  data,
  height = 300,
}: Props) {
  if (data.length === 0) return null;

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 20, right: 20, bottom: 10, left: 10 }}>
        <defs>
          <linearGradient id="cyanGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={CYAN} stopOpacity={0.3} />
            <stop offset="100%" stopColor={CYAN} stopOpacity={0.02} />
          </linearGradient>
        </defs>

        <CartesianGrid strokeDasharray="3 3" stroke={GRID_STROKE} />

        <XAxis
          dataKey="minute"
          tickFormatter={formatTime}
          tick={{
            fill: LABEL_COLOR,
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 10,
          }}
          axisLine={{ stroke: GRID_STROKE }}
          tickLine={{ stroke: GRID_STROKE }}
        />

        <YAxis
          tick={{
            fill: LABEL_COLOR,
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 10,
          }}
          axisLine={{ stroke: GRID_STROKE }}
          tickLine={{ stroke: GRID_STROKE }}
        />

        <Tooltip content={<CyanTooltip />} />

        <Area
          type="monotone"
          dataKey="count"
          stroke={CYAN}
          strokeWidth={2}
          fillOpacity={1}
          fill="url(#cyanGradient)"
          animationDuration={800}
          animationEasing="ease-out"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
