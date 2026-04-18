"use client";

import dynamic from "next/dynamic";
import { useEffect, useMemo, useRef, useState } from "react";
import type { SliverSessionDTO } from "./OperatorConsole";
import type { RedteamEvent } from "@/hooks/useRedteamEvents";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
  loading: () => (
    <div className="flex h-full items-center justify-center text-[11px] tracking-widest text-cyan-glow/30">
      LOADING GRAPH...
    </div>
  ),
});

interface Props {
  events: RedteamEvent[];
  selectedId: string | null;
  onSelect: (s: SliverSessionDTO) => void;
}

interface NodeRec {
  id: string;
  label: string;
  os?: string;
  active: boolean;
  isCentral?: boolean;
  raw?: SliverSessionDTO;
  [key: string]: unknown;
}

function colorForOs(os?: string, active = true): string {
  if (!active) return "#444";
  const o = (os || "").toLowerCase();
  if (o.includes("win")) return "#3B82F6";
  if (o.includes("linux")) return "#10B981";
  if (o.includes("darwin") || o.includes("mac")) return "#A78BFA";
  return "#06B6D4";
}

export default function BeaconGraph({ events, selectedId, onSelect }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState<{ w: number; h: number }>({ w: 360, h: 400 });
  const [sessions, setSessions] = useState<SliverSessionDTO[]>([]);

  // Mesure responsive du conteneur
  useEffect(() => {
    if (typeof window === "undefined") return;
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const r = el.getBoundingClientRect();
      setSize({ w: Math.max(200, r.width), h: Math.max(200, r.height) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Fetch initial
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/proxy/redteam/c2/sessions", {
          credentials: "include",
          cache: "no-store",
        });
        if (!res.ok) return;
        const data = (await res.json()) as SliverSessionDTO[];
        if (!cancelled && Array.isArray(data)) setSessions(data);
      } catch {
        // graceful
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Apply live events
  useEffect(() => {
    if (!events.length) return;
    setSessions((prev) => {
      let next = prev;
      for (const ev of [...events].reverse()) {
        const data = (ev.data as Record<string, unknown>) ?? {};
        const id = data.id as string | undefined;
        if (!id) continue;
        if (ev.type === "session.new") {
          if (!next.some((s) => s.id === id)) {
            next = [data as unknown as SliverSessionDTO, ...next];
          }
        } else if (ev.type === "session.dead") {
          next = next.map((s) => (s.id === id ? { ...s, active: false } : s));
        }
      }
      return next;
    });
  }, [events]);

  const graphData = useMemo(() => {
    const central: NodeRec = {
      id: "__c2__",
      label: "C2 Server",
      active: true,
      isCentral: true,
    };
    const nodes: NodeRec[] = [
      central,
      ...sessions.map((s) => ({
        id: s.id,
        label: s.hostname || s.id.slice(0, 8),
        os: s.os,
        active: !!s.active,
        raw: s,
      })),
    ];
    const links = sessions.map((s) => ({
      source: "__c2__",
      target: s.id,
    }));
    return { nodes, links };
  }, [sessions]);

  if (sessions.length === 0) {
    return (
      <div
        ref={containerRef}
        className="flex h-full items-center justify-center p-3 text-[11px] tracking-widest text-cyan-glow/30"
      >
        NO BEACONS — WAITING FOR IMPLANTS
      </div>
    );
  }

  return (
    <div ref={containerRef} className="h-full w-full">
      <ForceGraph2D
        graphData={graphData}
        width={size.w}
        height={size.h}
        backgroundColor="#000"
        nodeLabel={(n) => (n as unknown as NodeRec).label}
        nodeVal={(n) =>
          (n as unknown as NodeRec).isCentral
            ? 12
            : (n as unknown as NodeRec).active
              ? 6
              : 3
        }
        linkColor={() => "rgba(0, 229, 255, 0.25)"}
        linkWidth={1}
        nodeCanvasObject={(node, ctx, scale) => {
          const n = node as unknown as NodeRec & { x?: number; y?: number };
          if (n.x == null || n.y == null) return;
          const radius = n.isCentral ? 9 : n.active ? 5 : 3;
          ctx.beginPath();
          ctx.arc(n.x, n.y, radius, 0, 2 * Math.PI, false);
          ctx.fillStyle = n.isCentral
            ? "#FF3366"
            : colorForOs(n.os, n.active);
          ctx.fill();
          if (selectedId && n.id === selectedId) {
            ctx.lineWidth = 2 / scale;
            ctx.strokeStyle = "#00E5FF";
            ctx.stroke();
          }
          if (scale > 0.8) {
            ctx.font = `${10 / scale}px monospace`;
            ctx.fillStyle = "rgba(0, 229, 255, 0.7)";
            ctx.textAlign = "center";
            ctx.fillText(n.label, n.x, n.y + radius + 8 / scale);
          }
        }}
        onNodeClick={(node) => {
          const n = node as unknown as NodeRec;
          if (n.isCentral || !n.raw) return;
          onSelect(n.raw);
        }}
      />
    </div>
  );
}
