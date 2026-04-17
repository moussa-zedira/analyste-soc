import * as React from "react";
import { HudCard } from "./HudCard";

type Tone = "cyan" | "matrix" | "alert" | "warn" | "info" | "purple";

const TONE_VALUE: Record<Tone, string> = {
  cyan: "text-cyan-glow",
  matrix: "glow-matrix",
  alert: "glow-pink",
  warn: "glow-warn",
  info: "text-neon-blue",
  purple: "text-neon-purple",
};

export interface HudStatProps {
  label: React.ReactNode;
  value: React.ReactNode;
  hint?: React.ReactNode;
  tone?: Tone;
  trend?: { delta: number; label?: string };
  icon?: React.ReactNode;
  className?: string;
}

export function HudStat({
  label,
  value,
  hint,
  tone = "cyan",
  trend,
  icon,
  className = "",
}: HudStatProps) {
  return (
    <HudCard variant="glass" corners className={`p-4 ${className}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="hud-label">{label}</div>
          <div className={`mt-1.5 text-2xl font-bold tabular-nums ${TONE_VALUE[tone]}`}>
            {value}
          </div>
          {hint && (
            <div className="mt-1 text-[10px] text-cyan-glow/50 truncate">{hint}</div>
          )}
        </div>
        {icon && <div className="text-cyan-glow/40">{icon}</div>}
      </div>
      {trend && (
        <div className="mt-2 flex items-center gap-1 text-[10px] font-mono">
          <span
            className={
              trend.delta > 0
                ? "text-emerald-300"
                : trend.delta < 0
                ? "text-red-300"
                : "text-cyan-glow/50"
            }
          >
            {trend.delta > 0 ? "▲" : trend.delta < 0 ? "▼" : "—"}{" "}
            {Math.abs(trend.delta).toFixed(1)}%
          </span>
          {trend.label && (
            <span className="text-cyan-glow/40">{trend.label}</span>
          )}
        </div>
      )}
    </HudCard>
  );
}
