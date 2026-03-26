"use client";

import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import type { GraphData, GraphNode } from "@/lib/types";

const NODE_COLORS: Record<string, string> = {
  ip: "#3B82F6",
  user: "#22C55E",
  incident: "#EF4444",
};

const NODE_ICONS: Record<string, string> = {
  ip: "\uf0ac",       // globe
  user: "\uf007",     // user
  incident: "\uf071", // warning
};

interface Props {
  data: GraphData;
  width: number;
  height: number;
}

interface SimNode extends d3.SimulationNodeDatum {
  id: string;
  type: string;
  label: string;
  severity: string | null;
  event_count: number | null;
}

interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  weight: number;
}

/** Graphe interactif SVG des relations entre IP, utilisateurs et incidents. */
export function RelationshipGraph({ data, width, height }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  useEffect(() => {
    if (!svgRef.current || data.nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const nodes: SimNode[] = data.nodes.map((n) => ({ ...n }));
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const links: SimLink[] = data.edges
      .filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((e) => ({ source: e.source, target: e.target, weight: e.weight }));

    const g = svg.append("g");

    // Zoom
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 6])
      .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoom);

    // Adapt forces to node count for readability
    const nodeCount = nodes.length;
    const linkDist = nodeCount < 20 ? 150 : nodeCount < 40 ? 120 : 90;
    const chargeStr = nodeCount < 20 ? -300 : nodeCount < 40 ? -200 : -150;
    const collisionR = nodeCount < 20 ? 40 : 30;

    // Simulation with stronger repulsion for spacing
    const simulation = d3.forceSimulation<SimNode>(nodes)
      .force("link", d3.forceLink<SimNode, SimLink>(links).id((d) => d.id).distance(linkDist))
      .force("charge", d3.forceManyBody().strength(chargeStr))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(collisionR))
      .force("x", d3.forceX(width / 2).strength(0.05))
      .force("y", d3.forceY(height / 2).strength(0.05));

    // Defs: glow filter + arrow markers
    const defs = svg.append("defs");
    const filter = defs.append("filter").attr("id", "glow").attr("x", "-50%").attr("y", "-50%").attr("width", "200%").attr("height", "200%");
    filter.append("feGaussianBlur").attr("stdDeviation", "4").attr("result", "coloredBlur");
    const feMerge = filter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Links
    const link = g.append("g")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", "#374151")
      .attr("stroke-opacity", 0.6)
      .attr("stroke-width", (d) => Math.min(1 + d.weight * 0.3, 3));

    // Node groups
    const node = g.append("g")
      .selectAll<SVGGElement, SimNode>("g")
      .data(nodes)
      .join("g")
      .style("cursor", "pointer")
      .call(
        d3.drag<SVGGElement, SimNode>()
          .on("start", (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      );

    // Outer ring (glow)
    node.append("circle")
      .attr("r", (d) => d.type === "incident" ? 14 : 10)
      .attr("fill", "none")
      .attr("stroke", (d) => NODE_COLORS[d.type] || "#6B7280")
      .attr("stroke-width", 1.5)
      .attr("stroke-opacity", 0.2)
      .style("filter", "url(#glow)");

    // Inner circle
    node.append("circle")
      .attr("r", (d) => d.type === "incident" ? 10 : 7)
      .attr("fill", (d) => NODE_COLORS[d.type] + "33")
      .attr("stroke", (d) => NODE_COLORS[d.type] || "#6B7280")
      .attr("stroke-width", 1.5);

    // Type indicator (letter)
    node.append("text")
      .text((d) => d.type === "ip" ? "IP" : d.type === "user" ? "U" : "!")
      .attr("dy", 3.5)
      .attr("text-anchor", "middle")
      .attr("fill", (d) => NODE_COLORS[d.type])
      .attr("font-size", (d) => d.type === "incident" ? "9px" : "7px")
      .attr("font-family", "monospace")
      .attr("font-weight", "bold");

    // Labels below nodes
    node.append("text")
      .text((d) => {
        const l = d.label;
        return l.length > 20 ? l.slice(0, 18) + "..." : l;
      })
      .attr("dy", (d) => d.type === "incident" ? 22 : 18)
      .attr("text-anchor", "middle")
      .attr("fill", "#D1D5DB")
      .attr("font-size", "10px")
      .attr("font-family", "ui-monospace, monospace")
      .attr("paint-order", "stroke")
      .attr("stroke", "#0a0f1a")
      .attr("stroke-width", 3);

    // Hover effects
    node
      .on("mouseenter", function (_, d) {
        d3.select(this).select("circle:nth-child(2)")
          .transition().duration(150)
          .attr("r", d.type === "incident" ? 13 : 10)
          .attr("stroke-width", 2.5);
        // Highlight connected links
        link
          .attr("stroke-opacity", (l) => {
            const s = (l.source as SimNode).id;
            const t = (l.target as SimNode).id;
            return s === d.id || t === d.id ? 1 : 0.15;
          })
          .attr("stroke", (l) => {
            const s = (l.source as SimNode).id;
            const t = (l.target as SimNode).id;
            return s === d.id || t === d.id ? (NODE_COLORS[d.type] + "aa") : "#374151";
          });
      })
      .on("mouseleave", function (_, d) {
        d3.select(this).select("circle:nth-child(2)")
          .transition().duration(150)
          .attr("r", d.type === "incident" ? 10 : 7)
          .attr("stroke-width", 1.5);
        link
          .attr("stroke-opacity", 0.6)
          .attr("stroke", "#374151");
      });

    // Click handler
    node.on("click", (_, d) => {
      setSelectedNode({
        id: d.id,
        type: d.type as "ip" | "user" | "incident",
        label: d.label,
        severity: d.severity,
        event_count: d.event_count,
      });
    });

    // Tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d) => (d.source as SimNode).x!)
        .attr("y1", (d) => (d.source as SimNode).y!)
        .attr("x2", (d) => (d.target as SimNode).x!)
        .attr("y2", (d) => (d.target as SimNode).y!);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    // Auto-fit after stabilization
    simulation.on("end", () => {
      const bounds = (g.node() as SVGGElement)?.getBBox();
      if (!bounds || bounds.width === 0) return;
      const padding = 40;
      const scale = Math.min(
        (width - padding * 2) / bounds.width,
        (height - padding * 2) / bounds.height,
        1.5,
      );
      const tx = width / 2 - (bounds.x + bounds.width / 2) * scale;
      const ty = height / 2 - (bounds.y + bounds.height / 2) * scale;
      svg.transition().duration(500).call(
        zoom.transform,
        d3.zoomIdentity.translate(tx, ty).scale(scale),
      );
    });

    return () => { simulation.stop(); };
  }, [data, width, height]);

  return (
    <div className="relative h-full w-full">
      <svg
        ref={svgRef}
        width={width}
        height={height}
        className="bg-[#0a0f1a] rounded"
      />

      {selectedNode && (
        <div className="absolute right-4 top-4 w-64 rounded-lg border border-cyan-glow/20 bg-gray-900/95 p-4 shadow-xl backdrop-blur">
          <div className="mb-2 flex items-center justify-between">
            <span
              className="rounded px-2 py-0.5 text-[10px] font-bold tracking-wider"
              style={{
                backgroundColor: NODE_COLORS[selectedNode.type] + "33",
                color: NODE_COLORS[selectedNode.type],
              }}
            >
              {selectedNode.type.toUpperCase()}
            </span>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-gray-500 hover:text-gray-300 text-xs"
            >
              ✕
            </button>
          </div>
          <p className="text-sm font-semibold text-white font-mono break-all">
            {selectedNode.label}
          </p>
          {selectedNode.severity && (
            <p className="mt-1 text-[10px] text-gray-400">
              Severity: <span className={
                selectedNode.severity === "critical" ? "text-red-400" :
                selectedNode.severity === "high" ? "text-orange-400" :
                selectedNode.severity === "medium" ? "text-yellow-400" : "text-cyan-glow"
              }>{selectedNode.severity}</span>
            </p>
          )}
          {selectedNode.event_count != null && (
            <p className="text-[10px] text-gray-400">
              Events: <span className="text-cyan-glow">{selectedNode.event_count}</span>
            </p>
          )}
        </div>
      )}
    </div>
  );
}
