"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { DynamicRelationshipGraph } from "@/components/graph/DynamicRelationshipGraph";
import { getRelationshipGraph } from "@/lib/apiClient";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import type { GraphData } from "@/lib/types";

/** Page du graphe de relations entre IP, utilisateurs et incidents. */
export default function GraphPage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [data, setData] = useState<GraphData>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [injecting, setInjecting] = useState(false);

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
      setData(result);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  const handleInjectDemo = async () => {
    setInjecting(true);
    try {
      const BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "";
      const prefix = typeof window !== "undefined" && !BASE ? "/api/proxy" : BASE;
      const apiKey = typeof window !== "undefined" ? localStorage.getItem("api_key") || "" : "";
      await fetch(`${prefix}/stats/demo-data`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(apiKey ? { "X-API-Key": apiKey } : {}),
        },
      });
      // Recharger le graphe
      await loadGraph();
    } catch {
      setError("Erreur lors de l'injection des donnees");
    } finally {
      setInjecting(false);
    }
  };

  const isEmpty = !loading && data.nodes.length === 0;

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
          {!loading && data.nodes.length > 0 && (
            <div className="flex items-center gap-3">
              <span className="text-[10px] text-gray-500 font-mono">
                {data.nodes.length} nodes / {data.edges.length} edges
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
          style={{ height: "calc(100vh - 200px)" }}
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
              {/* Empty state illustration */}
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
                  Le graphe de relations necessite des evenements avec des adresses IP et des noms d&apos;utilisateur pour creer des connexions.
                </p>
              </div>
              <button
                onClick={handleInjectDemo}
                disabled={injecting}
                className="flex items-center gap-2 rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-5 py-2.5 text-[11px] font-bold tracking-widest text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-md active:scale-95 disabled:opacity-40"
              >
                {injecting ? (
                  <>
                    <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    INJECTION EN COURS...
                  </>
                ) : (
                  "GENERER DES DONNEES DE DEMO"
                )}
              </button>
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

      {/* Legend */}
      {!isEmpty && !loading && (
        <StaggerItem>
          <div className="flex items-center gap-6">
            {[
              { type: "IP Address", color: "#3B82F6" },
              { type: "User", color: "#22C55E" },
              { type: "Incident", color: "#EF4444" },
            ].map(({ type, color }) => (
              <div key={type} className="flex items-center gap-2">
                <span className="inline-block h-3 w-3 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-[10px] tracking-wider text-gray-500">{type}</span>
              </div>
            ))}
            <span className="ml-auto text-[9px] text-gray-600 tracking-wider">
              CLIQUER SUR UN NOEUD POUR VOIR LES DETAILS
            </span>
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
