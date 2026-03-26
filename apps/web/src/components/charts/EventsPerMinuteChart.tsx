"use client";

import { useEffect, useRef } from "react";
import * as d3 from "d3";
import type { EventsPerMinuteBucket } from "@/lib/types";

interface Props {
  data: EventsPerMinuteBucket[];
  width?: number;
  height?: number;
}

const CYAN = "#00E5FF";
const CYAN_DIM = "#00B8D4";
const GRID_COLOR = "#0F2A40";
const AXIS_COLOR = "#006B7D";
const LABEL_COLOR = "#4A7A8A";

export function EventsPerMinuteChart({
  data,
  width = 800,
  height = 300,
}: Props) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current || data.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const margin = { top: 20, right: 20, bottom: 40, left: 50 };
    const w = width - margin.left - margin.right;
    const h = height - margin.top - margin.bottom;

    // Glow filter
    const defs = svg.append("defs");
    const glowFilter = defs.append("filter").attr("id", "line-glow");
    glowFilter
      .append("feGaussianBlur")
      .attr("stdDeviation", "3")
      .attr("result", "blur");
    const merge = glowFilter.append("feMerge");
    merge.append("feMergeNode").attr("in", "blur");
    merge.append("feMergeNode").attr("in", "SourceGraphic");

    const g = svg
      .append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    const parseTime = d3.utcParse("%Y-%m-%dT%H:%M:%SZ");
    const parsed = data.map((d) => ({
      date: parseTime(d.minute)!,
      count: d.count,
      raw: d.minute,
    }));

    const x = d3
      .scaleUtc()
      .domain(d3.extent(parsed, (d) => d.date) as [Date, Date])
      .range([0, w]);
    const y = d3
      .scaleLinear()
      .domain([0, d3.max(parsed, (d) => d.count) || 1])
      .nice()
      .range([h, 0]);

    // Grid lines
    g.append("g")
      .attr("transform", `translate(0,${h})`)
      .call(
        d3
          .axisBottom(x)
          .ticks(6)
          .tickSize(-h)
          .tickFormat(() => ""),
      )
      .selectAll("line")
      .attr("stroke", GRID_COLOR)
      .attr("stroke-opacity", 0.6);

    // X axis
    g.append("g")
      .attr("transform", `translate(0,${h})`)
      .call(
        d3
          .axisBottom(x)
          .ticks(6)
          .tickFormat(
            d3.utcFormat("%H:%M") as (
              d: d3.NumberValue | Date,
              i: number,
            ) => string,
          ),
      )
      .selectAll("text")
      .attr("fill", LABEL_COLOR)
      .attr("font-family", "JetBrains Mono, monospace")
      .attr("font-size", "10px");

    // Y axis
    g.append("g")
      .call(d3.axisLeft(y).ticks(5))
      .selectAll("text")
      .attr("fill", LABEL_COLOR)
      .attr("font-family", "JetBrains Mono, monospace")
      .attr("font-size", "10px");

    // Gradient definition
    const gradient = defs
      .append("linearGradient")
      .attr("id", "area-gradient-cyan")
      .attr("x1", "0%")
      .attr("y1", "0%")
      .attr("x2", "0%")
      .attr("y2", "100%");
    gradient
      .append("stop")
      .attr("offset", "0%")
      .attr("stop-color", CYAN)
      .attr("stop-opacity", 0.25);
    gradient
      .append("stop")
      .attr("offset", "100%")
      .attr("stop-color", CYAN)
      .attr("stop-opacity", 0.02);

    // Area
    const area = d3
      .area<{ date: Date; count: number }>()
      .x((d) => x(d.date))
      .y0(h)
      .y1((d) => y(d.count))
      .curve(d3.curveMonotoneX);

    g.append("path")
      .datum(parsed)
      .attr("fill", "url(#area-gradient-cyan)")
      .attr("d", area);

    // Line
    const line = d3
      .line<{ date: Date; count: number }>()
      .x((d) => x(d.date))
      .y((d) => y(d.count))
      .curve(d3.curveMonotoneX);

    const linePath = g
      .append("path")
      .datum(parsed)
      .attr("fill", "none")
      .attr("stroke", CYAN)
      .attr("stroke-width", 2)
      .attr("filter", "url(#line-glow)")
      .attr("d", line);

    // Animate line drawing
    const totalLength = linePath.node()?.getTotalLength() ?? 0;
    linePath
      .attr("stroke-dasharray", `${totalLength} ${totalLength}`)
      .attr("stroke-dashoffset", totalLength)
      .transition()
      .duration(800)
      .ease(d3.easeQuadOut)
      .attr("stroke-dashoffset", 0);

    // Tooltip
    const tooltip = d3
      .select(svgRef.current.parentElement!)
      .append("div")
      .attr(
        "class",
        "pointer-events-none absolute z-50 rounded-md border border-cyan-500/20 bg-space-dark/95 px-3 py-2 text-xs text-cyan-300 shadow-xl backdrop-blur-sm opacity-0 transition-opacity duration-150",
      )
      .style("position", "absolute");

    const hoverLine = g
      .append("line")
      .attr("stroke", CYAN_DIM)
      .attr("stroke-width", 1)
      .attr("stroke-dasharray", "2,3")
      .attr("y1", 0)
      .attr("y2", h)
      .style("opacity", 0);

    const hoverDot = g
      .append("circle")
      .attr("r", 4)
      .attr("fill", CYAN)
      .attr("stroke", "#0B1C2D")
      .attr("stroke-width", 2)
      .attr("filter", "url(#line-glow)")
      .style("opacity", 0);

    g.append("rect")
      .attr("width", w)
      .attr("height", h)
      .attr("fill", "transparent")
      .on("mousemove", (event: MouseEvent) => {
        const [mx] = d3.pointer(event);
        const bisect = d3.bisector((d: { date: Date }) => d.date).left;
        const xDate = x.invert(mx);
        const idx = bisect(parsed, xDate, 1);
        const d0 = parsed[idx - 1];
        const d1 = parsed[idx];
        if (!d0) return;
        const d =
          d1 &&
          xDate.getTime() - d0.date.getTime() >
            d1.date.getTime() - xDate.getTime()
            ? d1
            : d0;

        const cx = x(d.date);
        const cy = y(d.count);

        hoverLine.attr("x1", cx).attr("x2", cx).style("opacity", 1);
        hoverDot.attr("cx", cx).attr("cy", cy).style("opacity", 1);

        const timeStr = d3.utcFormat("%H:%M")(d.date);
        tooltip
          .html(
            `<div class="font-semibold" style="color:#00E5FF">${d.count} events</div><div style="color:#4A7A8A">${timeStr}</div>`,
          )
          .style("opacity", "1")
          .style("left", `${cx + margin.left + 12}px`)
          .style("top", `${cy + margin.top - 20}px`);
      })
      .on("mouseleave", () => {
        hoverLine.style("opacity", 0);
        hoverDot.style("opacity", 0);
        tooltip.style("opacity", "0");
      });

    // Style axes
    svg.selectAll(".domain").attr("stroke", AXIS_COLOR).attr("stroke-opacity", 0.3);
    svg.selectAll(".tick line").attr("stroke", AXIS_COLOR).attr("stroke-opacity", 0.2);

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
