"use client";

import { useMemo } from "react";
import { getGeoEvents } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { GeoEvent } from "@/lib/types";

/** Minimal SVG world map with threat dots - no Leaflet needed for widget view */
export default function ThreatMapWidget({ refreshKey }: { refreshKey: number }) {
  const { data: geoEvents, loading } = useFetchData<GeoEvent[]>(
    (signal) => getGeoEvents({ limit: 50 }, { signal }),
    [],
    [refreshKey],
  );

  // Convert lat/lon to simple equirectangular projection
  const dots = useMemo(() => {
    return geoEvents.map((ev) => ({
      x: ((ev.lon + 180) / 360) * 100,
      y: ((90 - ev.lat) / 180) * 100,
      severity: ev.max_severity,
      ip: ev.src_ip,
      count: ev.event_count,
      country: ev.country,
    }));
  }, [geoEvents]);

  const severityColor = (sev: string) => {
    switch (sev) {
      case "critical": return "#EF4444";
      case "high": return "#F97316";
      case "medium": return "#EAB308";
      default: return "#00E5FF";
    }
  };

  if (loading) {
    return (
      <div className="space-y-2">
        <div className="skeleton h-4 w-32" />
        <div className="skeleton h-[180px] w-full" />
      </div>
    );
  }

  return (
    <div className="relative h-full min-h-[180px]">
      <svg viewBox="0 0 100 50" className="h-full w-full" preserveAspectRatio="xMidYMid meet">
        {/* Background */}
        <rect width="100" height="50" fill="#061320" rx="1" />

        {/* Grid lines */}
        {[0, 25, 50, 75, 100].map((x) => (
          <line key={`vl-${x}`} x1={x} y1="0" x2={x} y2="50" stroke="#0F2A40" strokeWidth="0.15" />
        ))}
        {[0, 12.5, 25, 37.5, 50].map((y) => (
          <line key={`hl-${y}`} x1="0" y1={y} x2="100" y2={y} stroke="#0F2A40" strokeWidth="0.15" />
        ))}

        {/* Equator */}
        <line x1="0" y1="25" x2="100" y2="25" stroke="#006B7D" strokeWidth="0.1" strokeDasharray="1 1" />

        {/* Simplified continent outlines */}
        <ellipse cx="28" cy="20" rx="10" ry="6" fill="none" stroke="#153550" strokeWidth="0.2" opacity="0.5" />
        <ellipse cx="52" cy="18" rx="12" ry="8" fill="none" stroke="#153550" strokeWidth="0.2" opacity="0.5" />
        <ellipse cx="75" cy="22" rx="10" ry="7" fill="none" stroke="#153550" strokeWidth="0.2" opacity="0.5" />
        <ellipse cx="52" cy="32" rx="6" ry="5" fill="none" stroke="#153550" strokeWidth="0.2" opacity="0.5" />
        <ellipse cx="28" cy="34" rx="5" ry="6" fill="none" stroke="#153550" strokeWidth="0.2" opacity="0.5" />
        <ellipse cx="82" cy="38" rx="5" ry="4" fill="none" stroke="#153550" strokeWidth="0.2" opacity="0.5" />

        {/* Threat dots */}
        {dots.map((dot, i) => {
          const color = severityColor(dot.severity);
          return (
            <g key={i}>
              <circle
                cx={dot.x}
                cy={dot.y / 2}
                r="1.2"
                fill={color}
                opacity="0.3"
              >
                <animate
                  attributeName="r"
                  values="1.2;2.5;1.2"
                  dur={`${2 + Math.random() * 2}s`}
                  repeatCount="indefinite"
                />
                <animate
                  attributeName="opacity"
                  values="0.3;0.1;0.3"
                  dur={`${2 + Math.random() * 2}s`}
                  repeatCount="indefinite"
                />
              </circle>
              <circle
                cx={dot.x}
                cy={dot.y / 2}
                r="0.5"
                fill={color}
                opacity="0.8"
              />
            </g>
          );
        })}

        {/* No data placeholder */}
        {dots.length === 0 && (
          <text x="50" y="26" textAnchor="middle" fill="#4A7A8A" fontSize="2.5" fontFamily="monospace">
            NO GEO DATA
          </text>
        )}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-1 right-1 flex items-center gap-2">
        {[
          { label: "LOW", color: "#00E5FF" },
          { label: "MED", color: "#EAB308" },
          { label: "HIGH", color: "#F97316" },
          { label: "CRIT", color: "#EF4444" },
        ].map(({ label, color }) => (
          <div key={label} className="flex items-center gap-0.5">
            <span className="block h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
            <span className="text-[7px] tracking-wider text-gray-600">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
