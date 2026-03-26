"use client";

import type { Event } from "@/lib/types";
import { SeverityBadge } from "@/components/Badge";

interface IncidentTimelineProps {
  events: Event[];
}

function severityDotColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "border-red-500 bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.5)]";
    case "high":
      return "border-orange-500 bg-orange-500 shadow-[0_0_6px_rgba(249,115,22,0.5)]";
    case "medium":
      return "border-yellow-500 bg-yellow-500 shadow-[0_0_6px_rgba(234,179,8,0.5)]";
    case "low":
      return "border-cyan-glow bg-cyan-glow shadow-[0_0_6px_rgba(0,229,255,0.5)]";
    default:
      return "border-gray-500 bg-gray-500";
  }
}

export function IncidentTimeline({ events }: IncidentTimelineProps) {
  const sorted = [...events].sort(
    (a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime(),
  );

  if (sorted.length === 0) {
    return (
      <p className="text-sm text-gray-500">
        No events to display.
      </p>
    );
  }

  return (
    <div className="relative pl-8">
      {/* Vertical line */}
      <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-gradient-to-b from-cyan-glow/30 via-cyan-glow/10 to-transparent" />

      {sorted.map((event, i) => (
        <div
          key={event.id}
          className="relative mb-6 last:mb-0"
          style={{
            animation: `slide-up 0.3s ease-out ${i * 0.05}s both`,
          }}
        >
          {/* Dot marker */}
          <div
            className={`absolute -left-5 top-1.5 h-3 w-3 rounded-full border-2 ${severityDotColor(event.severity)}`}
          />

          {/* Content card */}
          <div className="ml-2 rounded-md border border-cyan-glow/10 bg-space-mid/30 p-3 transition-colors hover:border-cyan-glow/20 hover:bg-space-mid/50">
            <div className="mb-1 flex items-center gap-2">
              <span className="font-mono text-xs text-cyan-glow/50">
                {new Date(event.ts).toLocaleString()}
              </span>
              <SeverityBadge value={event.severity} />
            </div>
            <div className="flex items-center gap-3 text-sm">
              <span className="font-medium text-gray-200">
                {event.event_type}
              </span>
              {event.src_ip && (
                <span className="font-mono text-xs text-cyan-glow/40">
                  {event.src_ip}
                </span>
              )}
              {event.username && (
                <span className="font-mono text-xs text-gray-500">
                  {event.username}
                </span>
              )}
            </div>
            {event.message && (
              <p className="mt-1 text-xs text-gray-500 line-clamp-2">
                {event.message}
              </p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
