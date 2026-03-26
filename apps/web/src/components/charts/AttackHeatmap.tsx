"use client";

import { useEffect, useRef } from "react";
import * as d3 from "d3";
import type { HeatmapCell } from "@/lib/types";

const DAYS = ["Lun", "Mar", "Mer", "Jeu", "Ven", "Sam", "Dim"];
const HOURS = Array.from({ length: 24 }, (_, i) =>
  `${String(i).padStart(2, "0")}:00`,
);

const LABEL_COLOR = "#4A7A8A";
const CELL_EMPTY = "#081A2B";

interface Props {
  data: HeatmapCell[];
  width?: number;
  height?: number;
}

export function AttackHeatmap({ data, width = 800, height = 280 }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current || data.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const margin = { top: 20, right: 80, bottom: 30, left: 50 };
    const w = width - margin.left - margin.right;
    const h = height - margin.top - margin.bottom;

    const g = svg
      .append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    const cellW = w / 24;
    const cellH = h / 7;

    const maxCount = d3.max(data, (d) => d.count) || 1;

    // Custom cyan -> orange -> red scale
    const color = d3
      .scaleSequential(
        d3.interpolateRgbBasis(["#003845", "#00B8D4", "#00E5FF", "#F97316", "#EF4444"]),
      )
      .domain([0, maxCount]);

    // Tooltip
    const tooltip = d3
      .select(svgRef.current.parentElement!)
      .append("div")
      .attr(
        "class",
        "pointer-events-none absolute z-50 rounded-md border border-cyan-500/20 bg-space-dark/95 px-3 py-2 text-xs text-cyan-300 shadow-xl backdrop-blur-sm opacity-0 transition-opacity duration-150",
      )
      .style("position", "absolute");

    // Cells
    g.selectAll("rect")
      .data(data)
      .join("rect")
      .attr("x", (d) => d.hour * cellW)
      .attr("y", (d) => d.day_of_week * cellH)
      .attr("width", cellW - 2)
      .attr("height", cellH - 2)
      .attr("rx", 2)
      .attr("fill", (d) => (d.count === 0 ? CELL_EMPTY : color(d.count)))
      .style("opacity", 0)
      .style("cursor", "pointer")
      .on("mouseenter", function (event: MouseEvent, d) {
        d3.select(this)
          .attr("stroke", "#00E5FF")
          .attr("stroke-width", 1.5)
          .attr("stroke-opacity", 0.6);
        const [mx, my] = d3.pointer(event, svgRef.current!);
        tooltip
          .html(
            `<div class="font-semibold" style="color:#00E5FF">${d.count} events</div><div style="color:#4A7A8A">${DAYS[d.day_of_week]} ${HOURS[d.hour]}</div>`,
          )
          .style("opacity", "1")
          .style("left", `${mx + 14}px`)
          .style("top", `${my - 10}px`);
      })
      .on("mouseleave", function () {
        d3.select(this).attr("stroke", "none");
        tooltip.style("opacity", "0");
      })
      .transition()
      .duration(400)
      .delay((_, i) => i * 2)
      .style("opacity", 1);

    // Day labels
    g.selectAll(".day-label")
      .data(DAYS)
      .join("text")
      .attr("x", -8)
      .attr("y", (_, i) => i * cellH + cellH / 2)
      .attr("text-anchor", "end")
      .attr("dominant-baseline", "middle")
      .attr("fill", LABEL_COLOR)
      .attr("font-size", "10px")
      .attr("font-family", "JetBrains Mono, monospace")
      .text((d) => d);

    // Hour labels (every 3h)
    g.selectAll(".hour-label")
      .data(HOURS.filter((_, i) => i % 3 === 0))
      .join("text")
      .attr("x", (_, i) => i * 3 * cellW + cellW / 2)
      .attr("y", h + 16)
      .attr("text-anchor", "middle")
      .attr("fill", LABEL_COLOR)
      .attr("font-size", "9px")
      .attr("font-family", "JetBrains Mono, monospace")
      .text((d) => d);

    // Legend
    const legendWidth = 12;
    const legendHeight = h;
    const legendX = w + 20;

    const legendScale = d3
      .scaleLinear()
      .domain([0, maxCount])
      .range([legendHeight, 0]);

    const legendAxis = d3.axisRight(legendScale).ticks(4).tickSize(0);

    // Legend gradient
    const defs = svg.append("defs");
    const lgGrad = defs
      .append("linearGradient")
      .attr("id", "heatmap-legend-space")
      .attr("x1", "0%")
      .attr("y1", "100%")
      .attr("x2", "0%")
      .attr("y2", "0%");

    const steps = 10;
    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      lgGrad
        .append("stop")
        .attr("offset", `${t * 100}%`)
        .attr("stop-color", color(t * maxCount));
    }

    g.append("rect")
      .attr("x", legendX)
      .attr("y", 0)
      .attr("width", legendWidth)
      .attr("height", legendHeight)
      .attr("rx", 3)
      .attr("fill", "url(#heatmap-legend-space)");

    g.append("g")
      .attr("transform", `translate(${legendX + legendWidth + 2}, 0)`)
      .call(legendAxis)
      .selectAll("text")
      .attr("fill", LABEL_COLOR)
      .attr("font-size", "9px")
      .attr("font-family", "JetBrains Mono, monospace");

    g.select(".domain").remove();

    return () => {
      tooltip.remove();
    };
  }, [data, width, height]);

  return (
    <div className="relative">
      <svg
        ref={svgRef}
        width={width}
        height={height}
        className="w-full"
        viewBox={`0 0 ${width} ${height}`}
      />
    </div>
  );
}
