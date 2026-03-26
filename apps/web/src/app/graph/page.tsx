"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { DynamicRelationshipGraph } from "@/components/graph/DynamicRelationshipGraph";
import { getRelationshipGraph } from "@/lib/apiClient";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import type { GraphData } from "@/lib/types";

const NODE_TYPES = [
  { key: "ip", label: "IP", color: "#3B82F6" },
  { key: "user", label: "User", color: "#22C55E" },
  { key: "incident", label: "Incident", color: "#EF4444" },
] as const;

const MAX_NODES_OPTIONS = [15, 30, 50, 100];

/** Page du graphe de relations entre IP, utilisateurs et incidents. */
export default function GraphPage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [rawData, setRawData] = useState<GraphData>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);


  // Filters
  const [visibleTypes, setVisibleTypes] = useState<Set<string>>(
    new Set(["ip", "user", "incident"]),
  );
  const [maxNodes, setMaxNodes] = useState(30);

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

  const loadGraph = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getRelationshipGraph({ limit: 200 });
      setRawData(result);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  // Filter + limit data
  const filteredData = useMemo<GraphData>(() => {
    if (rawData.nodes.length === 0) return rawData;

    // Count connections per node
    const connectionCount = new Map<string, number>();
    for (const edge of rawData.edges) {
      connectionCount.set(edge.source, (connectionCount.get(edge.source) || 0) + edge.weight);
      connectionCount.set(edge.target, (connectionCount.get(edge.target) || 0) + edge.weight);
    }

    // Filter by type, sort by connections, limit
    const filtered = rawData.nodes
      .filter((n) => visibleTypes.has(n.type))
      .sort((a, b) => (connectionCount.get(b.id) || 0) - (connectionCount.get(a.id) || 0))
      .slice(0, maxNodes);

    const nodeIds = new Set(filtered.map((n) => n.id));

    const edges = rawData.edges.filter(
      (e) => nodeIds.has(e.source) && nodeIds.has(e.target),
    );

    return { nodes: filtered, edges };
  }, [rawData, visibleTypes, maxNodes]);

  const toggleType = (type: string) => {
    setVisibleTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) {
        if (next.size > 1) next.delete(type); // keep at least 1
      } else {
        next.add(type);
      }
      return next;
    });
  };

  const isEmpty = !loading && rawData.nodes.length === 0;

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
              Relationship Graph
            </h1>
            <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
              IP // USER // INCIDENT CONNECTIONS
            </p>
          </div>
          {!loading && rawData.nodes.length > 0 && (
            <div className="flex items-center gap-3">
              <span className="text-[10px] text-gray-500 font-mono">
                {filteredData.nodes.length}/{rawData.nodes.length} nodes / {filteredData.edges.length} edges
              </span>
              <button
                onClick={loadGraph}
                className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-3 py-1.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors"
              >
                REFRESH
              </button>
            </div>
          )}
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Filters */}
      {!isEmpty && !loading && (
        <StaggerItem>
          <div className="flex items-center gap-4 flex-wrap">
            {/* Type filters */}
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-bold tracking-widest text-gray-500 uppercase">Filtres</span>
              {NODE_TYPES.map(({ key, label, color }) => (
                <button
                  key={key}
                  onClick={() => toggleType(key)}
                  className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[10px] font-bold tracking-wider transition-all ${
                    visibleTypes.has(key)
                      ? "border-opacity-40 bg-opacity-15"
                      : "border-gray-700 bg-transparent text-gray-600 opacity-40"
                  }`}
                  style={
                    visibleTypes.has(key)
                      ? { borderColor: color + "66", backgroundColor: color + "1a", color }
                      : undefined
                  }
                >
                  <span
                    className="inline-block h-2 w-2 rounded-full"
                    style={{ backgroundColor: visibleTypes.has(key) ? color : "#4B5563" }}
                  />
                  {label}
                </button>
              ))}
            </div>

            {/* Max nodes */}
            <div className="flex items-center gap-2 ml-auto">
              <span className="text-[9px] font-bold tracking-widest text-gray-500 uppercase">Limite</span>
              {MAX_NODES_OPTIONS.map((n) => (
                <button
                  key={n}
                  onClick={() => setMaxNodes(n)}
                  className={`rounded-md border px-2 py-1 text-[10px] font-mono font-bold transition-all ${
                    maxNodes === n
                      ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow"
                      : "border-gray-700 text-gray-500 hover:border-gray-600 hover:text-gray-400"
                  }`}
                >
                  {n}
                </button>
              ))}
            </div>
          </div>
        </StaggerItem>
      )}

      {error && (
        <StaggerItem>
          <div className="glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400">
            <span className="mr-2 text-red-500">&#x25B2;</span>
            {error}
          </div>
        </StaggerItem>
      )}

      <StaggerItem>
        <div
          ref={containerRef}
          className="glass-panel glass-panel-animated overflow-hidden"
          style={{ height: "calc(100vh - 260px)" }}
        >
          {loading ? (
            <div className="flex h-full flex-col items-center justify-center gap-3">
              <div className="relative h-12 w-12">
                <div className="absolute inset-0 rounded-full border-2 border-cyan-glow/20 animate-ping" />
                <div className="absolute inset-2 rounded-full border-2 border-t-cyan-glow border-transparent animate-spin" />
              </div>
              <p className="hud-label animate-pulse">LOADING GRAPH...</p>
            </div>
          ) : isEmpty ? (
            <div className="flex h-full flex-col items-center justify-center gap-6">
              <div className="relative">
                <svg width="120" height="120" viewBox="0 0 120 120" className="opacity-20">
                  <circle cx="30" cy="40" r="8" fill="#3B82F6" />
                  <circle cx="90" cy="35" r="8" fill="#22C55E" />
                  <circle cx="60" cy="85" r="10" fill="#EF4444" />
                  <line x1="30" y1="40" x2="90" y2="35" stroke="#4B5563" strokeWidth="1" strokeDasharray="4" />
                  <line x1="30" y1="40" x2="60" y2="85" stroke="#4B5563" strokeWidth="1" strokeDasharray="4" />
                  <line x1="90" y1="35" x2="60" y2="85" stroke="#4B5563" strokeWidth="1" strokeDasharray="4" />
                </svg>
              </div>
              <div className="text-center space-y-2">
                <p className="text-sm text-gray-400">Aucune donnee pour le graphe</p>
                <p className="text-[10px] text-gray-600 max-w-xs">
                  Le graphe se construit a partir des evenements reels detectes par le SIEM.
                  Utilisez le scanner ou attendez des evenements reseau.
                </p>
              </div>
            </div>
          ) : filteredData.nodes.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-3">
              <p className="text-sm text-gray-400">Aucun noeud avec ces filtres</p>
              <p className="text-[10px] text-gray-600">Activez au moins un type de noeud</p>
            </div>
          ) : (
            <DynamicRelationshipGraph
              data={filteredData}
              width={dimensions.width}
              height={dimensions.height}
            />
          )}
        </div>
      </StaggerItem>

      {/* Legend */}
      {!isEmpty && !loading && (
        <StaggerItem>
          <div className="flex items-center gap-6">
            {NODE_TYPES.map(({ key, label, color }) => (
              <div key={key} className="flex items-center gap-2">
                <span className="inline-block h-3 w-3 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-[10px] tracking-wider text-gray-500">{label}</span>
              </div>
            ))}
            <span className="ml-auto text-[9px] text-gray-600 tracking-wider">
              ZOOM MOLETTE // DRAG POUR DEPLACER // CLIC SUR NOEUD
            </span>
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
