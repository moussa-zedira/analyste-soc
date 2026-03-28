"use client";

import { useCallback, useState, useRef, useEffect } from "react";
import { useWebSocket, type WsMessage } from "@/lib/useWebSocket";

const severityStyles: Record<string, string> = {
  low: "border-cyan-glow/30 text-cyan-glow bg-cyan-glow/10",
  medium: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  high: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  critical: "border-red-500/30 text-red-400 bg-red-500/10",
};

export default function LiveFeedWidget({ refreshKey: _refreshKey }: { refreshKey: number }) {
  const [events, setEvents] = useState<Record<string, unknown>[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  const handleMessage = useCallback((msg: WsMessage) => {
    if (msg.type === "new_event") {
      setEvents((prev) => [msg.payload, ...prev].slice(0, 30));
    }
  }, []);

  const { connected } = useWebSocket({ onMessage: handleMessage });

  return (
    <div className="space-y-2">
      {/* Status bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="relative flex h-1.5 w-1.5">
            <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${connected ? "animate-ping bg-cyan-glow" : "bg-red-500"}`} />
            <span className={`relative inline-flex h-1.5 w-1.5 rounded-full ${connected ? "bg-cyan-glow" : "bg-red-500"}`} />
          </span>
          <span className="text-[8px] tracking-wider text-gray-500">
            {connected ? "LIVE" : "OFFLINE"}
          </span>
        </div>
        {events.length > 0 && (
          <span className="text-[8px] tracking-wider text-cyan-glow/40">
            {events.length} EVENTS
          </span>
        )}
      </div>

      {/* Event list */}
      <div ref={scrollRef} className="max-h-[260px] space-y-0.5 overflow-y-auto">
        {events.length === 0 ? (
          <div className="flex h-[100px] items-center justify-center">
            <p className="text-[9px] tracking-wider text-gray-600">
              AWAITING LIVE EVENTS...
            </p>
          </div>
        ) : (
          events.map((ev, i) => {
            const sev = String(ev.severity ?? "low").toLowerCase();
            return (
              <div
                key={`${i}-${ev.ts}`}
                className="flex items-center gap-2 rounded px-2 py-1.5 text-[10px] transition-colors hover:bg-cyan-glow/5"
                style={{
                  animation: i < 3 ? `slide-up 0.3s ease-out ${i * 0.05}s both` : "none",
                }}
              >
                <span className="shrink-0 font-mono text-[8px] text-cyan-glow/30">
                  {String(ev.ts ?? "").slice(11, 19)}
                </span>
                <span className={`shrink-0 rounded border px-1 py-0.5 text-[7px] font-bold tracking-wider ${severityStyles[sev] ?? severityStyles.low}`}>
                  {sev.slice(0, 3).toUpperCase()}
                </span>
                <span className="shrink-0 font-medium text-gray-400">
                  {String(ev.event_type ?? "")}
                </span>
                <span className="flex-1 truncate text-gray-600">
                  {String(ev.message ?? "")}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
