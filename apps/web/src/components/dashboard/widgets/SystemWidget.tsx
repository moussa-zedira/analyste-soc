"use client";

import { useState, useEffect } from "react";

interface Meter {
  label: string;
  value: number;
  color: string;
}

export default function SystemWidget({ refreshKey: _refreshKey }: { refreshKey: number }) {
  const [meters, setMeters] = useState<Meter[]>([
    { label: "CPU LOAD", value: 52, color: "#00E5FF" },
    { label: "MEMORY", value: 61, color: "#00B8D4" },
    { label: "NETWORK I/O", value: 34, color: "#006B7D" },
    { label: "DISK I/O", value: 18, color: "#003845" },
  ]);

  // Simulate drifting values
  useEffect(() => {
    const t = setInterval(() => {
      setMeters((prev) =>
        prev.map((m) => ({
          ...m,
          value: Math.min(95, Math.max(5, m.value + (Math.random() * 10 - 5))),
        }))
      );
    }, 3000);
    return () => clearInterval(t);
  }, []);

  const getBarColor = (value: number) => {
    if (value >= 80) return "from-red-500/60 to-red-500";
    if (value >= 60) return "from-orange-500/60 to-orange-500";
    return "from-cyan-glow/60 to-cyan-glow";
  };

  return (
    <div className="space-y-3">
      {meters.map(({ label, value }) => (
        <div key={label}>
          <div className="mb-1 flex items-center justify-between">
            <span className="text-[8px] font-bold tracking-widest text-gray-500">{label}</span>
            <span className={`text-[10px] font-mono tabular-nums ${
              value >= 80 ? "text-red-400" : value >= 60 ? "text-orange-400" : "text-cyan-glow/60"
            }`}>
              {Math.round(value)}%
            </span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-space-mid">
            <div
              className={`h-full rounded-full bg-gradient-to-r ${getBarColor(value)} transition-all duration-1000`}
              style={{ width: `${value}%` }}
            />
          </div>
        </div>
      ))}

      {/* Uptime display */}
      <div className="mt-2 flex items-center justify-between border-t border-cyan-glow/10 pt-2">
        <span className="text-[8px] tracking-widest text-gray-600">SYS.STATUS</span>
        <span className="flex items-center gap-1.5 text-[9px] tracking-wider text-cyan-glow/60">
          <span className="h-1.5 w-1.5 rounded-full bg-green-400 shadow-[0_0_4px_rgba(74,222,128,0.5)]" />
          OPERATIONAL
        </span>
      </div>
    </div>
  );
}
