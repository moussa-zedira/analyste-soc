"use client";

import { useCallback, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { GraphData, GraphNode } from "@/lib/types";

const NODE_COLORS: Record<string, string> = {
  ip: "#3B82F6",
  user: "#22C55E",
  incident: "#EF4444",
};

interface Props {
  data: GraphData;
  width: number;
  height: number;
}

export function RelationshipGraph({ data, width, height }: Props) {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fgRef = useRef<any>(null);

  const graphData = {
    nodes: data.nodes.map((n) => ({ ...n })),
    links: data.edges.map((e) => ({
      source: e.source,
      target: e.target,
      weight: e.weight,
    })),
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleNodeClick = useCallback((node: any) => {
    setSelectedNode(node as GraphNode);
    if (fgRef.current) {
      fgRef.current.centerAt(node.x, node.y, 500);
      fgRef.current.zoom(3, 500);
    }
  }, []);

  const nodeCanvasObject = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const label = node.label || node.id;
      const fontSize = 12 / globalScale;
      const size = node.type === "incident" ? 6 : 4;

      ctx.beginPath();
      ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
      ctx.fillStyle = NODE_COLORS[node.type] || "#6B7280";
      ctx.fill();

      if (selectedNode?.id === node.id) {
        ctx.strokeStyle = "#FFFFFF";
        ctx.lineWidth = 2 / globalScale;
        ctx.stroke();
      }

      if (globalScale > 1.5) {
        ctx.font = `${fontSize}px sans-serif`;
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        ctx.fillStyle = "#D1D5DB";
        ctx.fillText(label, node.x, node.y + size + 2);
      }
    },
    [selectedNode],
  );

  return (
    <div className="relative">
      <ForceGraph2D
        ref={fgRef}
        graphData={graphData}
        width={width}
        height={height}
        backgroundColor="#111827"
        nodeCanvasObject={nodeCanvasObject}
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        linkColor={() => "#4B5563"}
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        linkWidth={(link: any) => Math.min(1 + link.weight * 0.5, 5)}
        onNodeClick={handleNodeClick}
      />

      {selectedNode && (
        <div className="absolute right-4 top-4 w-64 rounded-lg border border-gray-700 bg-gray-900 p-4 shadow-xl">
          <div className="mb-2 flex items-center justify-between">
            <span
              className="rounded px-2 py-0.5 text-xs font-medium"
              style={{
                backgroundColor: NODE_COLORS[selectedNode.type] + "33",
                color: NODE_COLORS[selectedNode.type],
              }}
            >
              {selectedNode.type.toUpperCase()}
            </span>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-gray-500 hover:text-gray-300"
            >
              ✕
            </button>
          </div>
          <p className="text-sm font-semibold text-white">
            {selectedNode.label}
          </p>
          {selectedNode.severity && (
            <p className="text-xs text-gray-400">
              Severity: {selectedNode.severity}
            </p>
          )}
          {selectedNode.event_count != null && (
            <p className="text-xs text-gray-400">
              Events: {selectedNode.event_count}
            </p>
          )}
        </div>
      )}

      <div className="absolute bottom-4 left-4 flex gap-4 rounded bg-gray-900/80 px-3 py-2">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1.5">
            <span
              className="inline-block h-3 w-3 rounded-full"
              style={{ backgroundColor: color }}
            />
            <span className="text-xs capitalize text-gray-400">{type}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
