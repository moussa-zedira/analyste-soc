"use client";

import { useEffect, useRef } from "react";
import {
  MapContainer,
  TileLayer,
  CircleMarker,
  Popup,
  useMap,
} from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import type { GeoEvent } from "@/lib/types";

const SEVERITY_COLORS: Record<string, string> = {
  low: "#00E5FF",
  medium: "#EAB308",
  high: "#F97316",
  critical: "#EF4444",
};

const SEVERITY_ORDER: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

interface Props {
  data: GeoEvent[];
}

/* ── Pulsing circle markers via CSS ── */
function PulsingMarker({
  geo,
  maxCount,
}: {
  geo: GeoEvent;
  maxCount: number;
}) {
  const map = useMap();
  const markerRef = useRef<L.CircleMarker | null>(null);
  const color = SEVERITY_COLORS[geo.max_severity] || "#00E5FF";
  const baseRadius = Math.min(
    5 + Math.log2(geo.event_count + 1) * 3,
    22,
  );

  // Normalize size based on event count relative to max
  const intensity = maxCount > 0 ? geo.event_count / maxCount : 0.5;

  return (
    <>
      {/* Outer pulse ring */}
      <CircleMarker
        center={[geo.lat, geo.lon]}
        radius={baseRadius + 4}
        pathOptions={{
          color,
          fillColor: color,
          fillOpacity: 0.1,
          weight: 1,
          opacity: 0.3,
          className: "animate-map-pulse",
        }}
      />
      {/* Main marker */}
      <CircleMarker
        ref={(ref) => {
          markerRef.current = ref as unknown as L.CircleMarker;
        }}
        center={[geo.lat, geo.lon]}
        radius={baseRadius}
        pathOptions={{
          color,
          fillColor: color,
          fillOpacity: 0.5 + intensity * 0.3,
          weight: 1.5,
          opacity: 0.8,
        }}
      >
        <Popup className="threat-popup">
          <div
            style={{
              background: "#0B1C2D",
              border: `1px solid ${color}40`,
              borderRadius: "8px",
              padding: "12px 14px",
              minWidth: "200px",
              color: "#c8e6f0",
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "11px",
            }}
          >
            {/* Header */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                marginBottom: "8px",
                paddingBottom: "8px",
                borderBottom: `1px solid ${color}20`,
              }}
            >
              <div
                style={{
                  width: "8px",
                  height: "8px",
                  borderRadius: "50%",
                  background: color,
                  boxShadow: `0 0 8px ${color}80`,
                }}
              />
              <span
                style={{
                  fontFamily: "'Orbitron', sans-serif",
                  fontWeight: 700,
                  fontSize: "12px",
                  color,
                  letterSpacing: "0.1em",
                }}
              >
                {geo.src_ip}
              </span>
            </div>
            {/* Details */}
            <div style={{ display: "grid", gap: "4px" }}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                }}
              >
                <span style={{ color: "#4A7A8A", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.15em" }}>
                  Location
                </span>
                <span style={{ color: "#c8e6f0" }}>
                  {geo.city}, {geo.country}
                </span>
              </div>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                }}
              >
                <span style={{ color: "#4A7A8A", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.15em" }}>
                  Events
                </span>
                <span style={{ color, fontWeight: 700 }}>
                  {geo.event_count}
                </span>
              </div>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                }}
              >
                <span style={{ color: "#4A7A8A", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.15em" }}>
                  Severity
                </span>
                <span
                  style={{
                    color,
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.1em",
                  }}
                >
                  {geo.max_severity}
                </span>
              </div>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                }}
              >
                <span style={{ color: "#4A7A8A", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.15em" }}>
                  Coords
                </span>
                <span style={{ color: "#6B8A9A", fontSize: "10px" }}>
                  {geo.lat.toFixed(3)}, {geo.lon.toFixed(3)}
                </span>
              </div>
            </div>
            {/* Threat bar */}
            <div style={{ marginTop: "8px" }}>
              <div
                style={{
                  height: "3px",
                  borderRadius: "2px",
                  background: "#0F2A40",
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: `${Math.min(intensity * 100, 100)}%`,
                    borderRadius: "2px",
                    background: `linear-gradient(90deg, ${color}80, ${color})`,
                  }}
                />
              </div>
            </div>
          </div>
        </Popup>
      </CircleMarker>
    </>
  );
}

export default function ThreatMap({ data }: Props) {
  const maxCount = Math.max(1, ...data.map((g) => g.event_count));

  // Sort so critical markers render on top
  const sorted = [...data].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.max_severity] ?? 0) -
      (SEVERITY_ORDER[b.max_severity] ?? 0),
  );

  return (
    <MapContainer
      center={[30, 0]}
      zoom={2}
      className="h-full w-full rounded-lg threat-map"
      style={{ minHeight: "500px", background: "#061320" }}
      zoomControl={false}
      attributionControl={false}
    >
      <TileLayer
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        attribution='&copy; <a href="https://carto.com/">CARTO</a>'
      />
      {sorted.map((geo) => (
        <PulsingMarker key={geo.src_ip} geo={geo} maxCount={maxCount} />
      ))}
    </MapContainer>
  );
}
