"use client";

import { useEffect, useRef, useState } from "react";
import { DynamicRelationshipGraph } from "@/components/graph/DynamicRelationshipGraph";
import { getRelationshipGraph } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { GraphData } from "@/lib/types";

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
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Graphe de Relations</h1>
      <p className="text-sm text-gray-400">
        Connexions entre IPs, utilisateurs et incidents
      </p>

      {error && (
        <div className="rounded border border-red-800 bg-red-950/30 px-4 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      <div
        ref={containerRef}
        className="rounded-lg border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900"
        style={{ height: "calc(100vh - 200px)" }}
      >
        {loading ? (
          <div className="flex h-full items-center justify-center">
            <p className="text-gray-500">Chargement du graphe...</p>
          </div>
        ) : (
          <DynamicRelationshipGraph
            data={data}
            width={dimensions.width}
            height={dimensions.height}
          />
        )}
      </div>
    </div>
  );
}
