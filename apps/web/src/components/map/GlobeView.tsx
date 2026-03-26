"use client";

import { useEffect, useRef, useCallback } from "react";
import type { GeoEvent } from "@/lib/types";
import type { GlobeInstance } from "globe.gl";

const SEVERITY_COLORS: Record<string, string> = {
  low: "#00E5FF",
  medium: "#EAB308",
  high: "#F97316",
  critical: "#EF4444",
};

interface Props {
  data: GeoEvent[];
  width: number;
  height: number;
}

interface GlobePoint {
  lat: number;
  lng: number;
  altitude: number;
  radius: number;
  color: string;
  label: string;
  severity: string;
  event_count: number;
}

interface GlobeArc {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  color: string;
}

export default function GlobeView({ data, width, height }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const globeRef = useRef<GlobeInstance | null>(null);

  const buildPoints = useCallback((): GlobePoint[] => {
    const maxCount = Math.max(1, ...data.map((g) => g.event_count));
    return data.map((geo) => {
      const color = SEVERITY_COLORS[geo.max_severity] || "#00E5FF";
      const scaledAltitude = 0.01 + (geo.event_count / maxCount) * 0.29;
      const radius = 0.3 + Math.log2(Math.max(1, geo.event_count)) * 0.15;
      return {
        lat: geo.lat,
        lng: geo.lon,
        altitude: scaledAltitude,
        radius,
        color,
        severity: geo.max_severity,
        event_count: geo.event_count,
        label: `
          <div style="
            background: rgba(11,28,45,0.95);
            border: 1px solid ${color}60;
            border-radius: 8px;
            padding: 10px 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: #c8e6f0;
            min-width: 180px;
            backdrop-filter: blur(8px);
          ">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;padding-bottom:6px;border-bottom:1px solid ${color}30;">
              <div style="width:7px;height:7px;border-radius:50%;background:${color};box-shadow:0 0 8px ${color}80;"></div>
              <span style="font-weight:700;color:${color};letter-spacing:0.1em;font-size:12px;">${geo.src_ip}</span>
            </div>
            <div style="display:grid;gap:3px;">
              <div style="display:flex;justify-content:space-between;">
                <span style="color:#4A7A8A;font-size:9px;text-transform:uppercase;letter-spacing:0.15em;">Location</span>
                <span>${geo.city}, ${geo.country}</span>
              </div>
              <div style="display:flex;justify-content:space-between;">
                <span style="color:#4A7A8A;font-size:9px;text-transform:uppercase;letter-spacing:0.15em;">Events</span>
                <span style="color:${color};font-weight:700;">${geo.event_count}</span>
              </div>
              <div style="display:flex;justify-content:space-between;">
                <span style="color:#4A7A8A;font-size:9px;text-transform:uppercase;letter-spacing:0.15em;">Severity</span>
                <span style="color:${color};font-weight:700;text-transform:uppercase;letter-spacing:0.1em;">${geo.max_severity}</span>
              </div>
            </div>
          </div>
        `,
      };
    });
  }, [data]);

  const buildArcs = useCallback((): GlobeArc[] => {
    if (data.length < 2) return [];
    const arcs: GlobeArc[] = [];
    // Create arcs from high/critical severity points to nearby points
    const sevOrder: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
    const sorted = [...data].sort(
      (a, b) => (sevOrder[b.max_severity] ?? 0) - (sevOrder[a.max_severity] ?? 0),
    );
    // Take top sources (high severity) and connect them to a few nearby targets
    const sources = sorted.slice(0, Math.min(15, sorted.length));
    const targets = sorted.slice(0, Math.min(30, sorted.length));

    for (const src of sources) {
      const color = SEVERITY_COLORS[src.max_severity] || "#00E5FF";
      // Connect to 1-2 other points
      let connected = 0;
      for (const tgt of targets) {
        if (tgt.src_ip === src.src_ip) continue;
        if (connected >= 2) break;
        arcs.push({
          startLat: src.lat,
          startLng: src.lon,
          endLat: tgt.lat,
          endLng: tgt.lon,
          color,
        });
        connected++;
      }
    }
    return arcs;
  }, [data]);

  useEffect(() => {
    if (!containerRef.current) return;

    let cancelled = false;

    import("globe.gl").then((mod) => {
      if (cancelled || !containerRef.current) return;

      const Globe = mod.default;
      const globe = new Globe(containerRef.current);

      globe
        .globeImageUrl("//unpkg.com/three-globe/example/img/earth-night.jpg")
        .bumpImageUrl("//unpkg.com/three-globe/example/img/earth-topology.png")
        .backgroundImageUrl("")
        .width(width)
        .height(height)
        .atmosphereColor("#00E5FF")
        .atmosphereAltitude(0.25)
        .pointsData(buildPoints())
        .pointLat("lat")
        .pointLng("lng")
        .pointAltitude("altitude")
        .pointRadius("radius")
        .pointColor("color")
        .pointLabel("label")
        .arcsData(buildArcs())
        .arcStartLat("startLat")
        .arcStartLng("startLng")
        .arcEndLat("endLat")
        .arcEndLng("endLng")
        .arcColor("color")
        .arcDashLength(0.4)
        .arcDashGap(0.2)
        .arcDashAnimateTime(1500)
        .arcStroke(0.5);

      // Enable auto-rotation
      const controls = globe.controls();
      if (controls) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.5;
        controls.enableZoom = true;
      }

      globeRef.current = globe;
    });

    return () => {
      cancelled = true;
      // Clean up: remove canvas from DOM
      if (containerRef.current) {
        while (containerRef.current.firstChild) {
          containerRef.current.removeChild(containerRef.current.firstChild);
        }
      }
      globeRef.current = null;
    };
    // Only run on mount / unmount; data updates handled separately
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Update data when props change (without re-creating the globe)
  useEffect(() => {
    if (!globeRef.current) return;
    const g = globeRef.current;
    if (typeof g.pointsData === "function") {
      g.pointsData(buildPoints());
    }
    if (typeof g.arcsData === "function") {
      g.arcsData(buildArcs());
    }
  }, [data, buildPoints, buildArcs]);

  // Update dimensions when width/height change
  useEffect(() => {
    if (!globeRef.current) return;
    const g = globeRef.current;
    if (typeof g.width === "function") g.width(width);
    if (typeof g.height === "function") g.height(height);
  }, [width, height]);

  return (
    <div
      ref={containerRef}
      style={{ width, height, background: "transparent" }}
    />
  );
}
