"use client";

import { useEffect, useRef, useState } from "react";
import { DynamicRelationshipGraph } from "@/components/graph/DynamicRelationshipGraph";
import { getRelationshipGraph } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import type { GraphData } from "@/lib/types";

/** Page du graphe de relations entre IP, utilisateurs et incidents. */
export default function GraphPage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  useEffect(() => {
    const updateSize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight,
        });
      }
    };
    updateSize();
    window.addEventListener("resize", updateSize);
    return () => window.removeEventListener("resize", updateSize);
  }, []);

  const { data, loading, error } = useFetchData<GraphData>(
    (signal) => getRelationshipGraph({ limit: 200 }, { signal }),
    { nodes: [], edges: [] },
    [],
  );

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Relationship Graph
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            IP // USER // INCIDENT CONNECTIONS
          </p>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {error && (
        <StaggerItem>
          <div className="animate-slide-up glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400">
            <span className="mr-2 text-red-500">&#x25B2;</span>
            {error}
          </div>
        </StaggerItem>
      )}

      <StaggerItem>
        <div
          ref={containerRef}
          className="glass-panel glass-panel-animated overflow-hidden"
          style={{ height: "calc(100vh - 200px)" }}
        >
          {loading ? (
            <div className="flex h-full flex-col items-center justify-center gap-3">
              <svg
                className="h-8 w-8 animate-spin text-cyan-glow/50"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              <p className="hud-label animate-pulse">LOADING GRAPH...</p>
            </div>
          ) : (
            <DynamicRelationshipGraph
              data={data}
              width={dimensions.width}
              height={dimensions.height}
            />
          )}
        </div>
      </StaggerItem>
    </PageTransition>
  );
}
