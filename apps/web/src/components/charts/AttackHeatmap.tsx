"use client";

/**
 * Carte de chaleur des attaques par jour de semaine et heure.
 * Rendu SVG pur avec cellules React, transitions CSS et tooltip React-driven.
 */

import { useMemo, useState, useCallback } from "react";
import type { HeatmapCell } from "@/lib/types";

const DAYS = ["Lun", "Mar", "Mer", "Jeu", "Ven", "Sam", "Dim"];
const HOURS = Array.from({ length: 24 }, (_, i) =>
  `${String(i).padStart(2, "0")}:00`,
);

const CYAN = "#00E5FF";
const LABEL_COLOR = "#4A7A8A";
const CELL_EMPTY = "#081A2B";
const GRID_STROKE = "#0F2A40";

interface Props {
  /** Donnees : tableau de cellules jour/heure/count */
  data: HeatmapCell[];
  /** Largeur optionnelle (pourcentage par defaut) */
  width?: number;
  /** Hauteur optionnelle */
  height?: number;
}

/**
 * Interpole lineairement entre deux couleurs RGB.
 */
function lerpColor(
  [r1, g1, b1]: [number, number, number],
  [r2, g2, b2]: [number, number, number],
  t: number,
): string {
  const r = Math.round(r1 + (r2 - r1) * t);
  const g = Math.round(g1 + (g2 - g1) * t);
  const b = Math.round(b1 + (b2 - b1) * t);
  return `rgb(${r},${g},${b})`;
}

/**
 * Echelle de couleurs cyan -> orange -> rouge.
 * Renvoie une couleur CSS pour une valeur normalisee [0, 1].
 */
function colorScale(t: number): string {
  // 5 etapes : #003845 -> #00B8D4 -> #00E5FF -> #F97316 -> #EF4444
  const stops: Array<[number, [number, number, number]]> = [
    [0, [0, 56, 69]],
    [0.25, [0, 184, 212]],
    [0.5, [0, 229, 255]],
    [0.75, [249, 115, 22]],
    [1, [239, 68, 68]],
  ];

  if (t <= 0) return lerpColor(stops[0][1], stops[0][1], 0);
  if (t >= 1) return lerpColor(stops[4][1], stops[4][1], 0);

  for (let i = 0; i < stops.length - 1; i++) {
    const [t0, c0] = stops[i];
    const [t1, c1] = stops[i + 1];
    if (t >= t0 && t <= t1) {
      return lerpColor(c0, c1, (t - t0) / (t1 - t0));
    }
  }
  return lerpColor(stops[4][1], stops[4][1], 0);
}

/** Composant principal : heatmap des attaques */
export function AttackHeatmap({ data, width = 800, height = 280 }: Props) {
  const [hovered, setHovered] = useState<{
    cell: HeatmapCell;
    x: number;
    y: number;
  } | null>(null);

  const maxCount = useMemo(
    () => Math.max(1, ...data.map((d) => d.count)),
    [data],
  );

  /** Genere les stops SVG du degrade de legende */
  const legendStops = useMemo(() => {
    const n = 10;
    return Array.from({ length: n + 1 }, (_, i) => {
      const t = i / n;
      return { offset: `${t * 100}%`, color: colorScale(t) };
    });
  }, []);

  const margin = { top: 20, right: 80, bottom: 30, left: 50 };
  const w = width - margin.left - margin.right;
  const h = height - margin.top - margin.bottom;
  const cellW = w / 24;
  const cellH = h / 7;
  const legendWidth = 12;

  const handleMouseEnter = useCallback(
    (cell: HeatmapCell, e: React.MouseEvent<SVGRectElement>) => {
      const svg = e.currentTarget.closest("svg");
      if (!svg) return;
      const rect = svg.getBoundingClientRect();
      setHovered({
        cell,
        x: e.clientX - rect.left + 14,
        y: e.clientY - rect.top - 10,
      });
    },
    [],
  );

  const handleMouseLeave = useCallback(() => {
    setHovered(null);
  }, []);

  if (data.length === 0) return null;

  return (
    <div className="relative" style={{ width: "100%" }}>
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className="w-full"
        style={{ fontFamily: "JetBrains Mono, monospace" }}
      >
        <defs>
          {/* Degrade vertical pour la legende */}
          <linearGradient
            id="heatmap-legend-gradient"
            x1="0%"
            y1="100%"
            x2="0%"
            y2="0%"
          >
            {legendStops.map((s, i) => (
              <stop key={i} offset={s.offset} stopColor={s.color} />
            ))}
          </linearGradient>

          {/* Filtre de lueur pour les cellules survolees */}
          <filter id="cell-glow">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <g transform={`translate(${margin.left},${margin.top})`}>
          {/* Cellules de la heatmap */}
          {data.map((cell, i) => {
            const x = cell.hour * cellW;
            const y = cell.day_of_week * cellH;
            const fill =
              cell.count === 0
                ? CELL_EMPTY
                : colorScale(cell.count / maxCount);
            const isHovered =
              hovered?.cell.day_of_week === cell.day_of_week &&
              hovered?.cell.hour === cell.hour;

            return (
              <rect
                key={`${cell.day_of_week}-${cell.hour}`}
                x={x}
                y={y}
                width={cellW - 2}
                height={cellH - 2}
                rx={2}
                fill={fill}
                stroke={isHovered ? CYAN : "none"}
                strokeWidth={isHovered ? 1.5 : 0}
                strokeOpacity={isHovered ? 0.6 : 0}
                filter={isHovered ? "url(#cell-glow)" : undefined}
                cursor="pointer"
                style={{
                  opacity: 1,
                  transform: isHovered ? "scale(1.05)" : "scale(1)",
                  transformOrigin: `${x + (cellW - 2) / 2}px ${y + (cellH - 2) / 2}px`,
                  transition: `opacity 0.4s ease ${i * 2}ms, transform 0.15s ease`,
                  animation: `heatmapFadeIn 0.4s ease ${i * 2}ms both`,
                }}
                onMouseEnter={(e) => handleMouseEnter(cell, e)}
                onMouseLeave={handleMouseLeave}
              />
            );
          })}

          {/* Labels des jours (axe Y) */}
          {DAYS.map((day, i) => (
            <text
              key={day}
              x={-8}
              y={i * cellH + cellH / 2}
              textAnchor="end"
              dominantBaseline="middle"
              fill={LABEL_COLOR}
              fontSize={10}
            >
              {day}
            </text>
          ))}

          {/* Labels des heures (axe X, toutes les 3h) */}
          {HOURS.filter((_, i) => i % 3 === 0).map((hour, i) => (
            <text
              key={hour}
              x={i * 3 * cellW + cellW / 2}
              y={h + 16}
              textAnchor="middle"
              fill={LABEL_COLOR}
              fontSize={9}
            >
              {hour}
            </text>
          ))}

          {/* Barre de legende */}
          <rect
            x={w + 20}
            y={0}
            width={legendWidth}
            height={h}
            rx={3}
            fill="url(#heatmap-legend-gradient)"
          />

          {/* Ticks de legende */}
          {[0, 0.25, 0.5, 0.75, 1].map((t) => {
            const val = Math.round(t * maxCount);
            const ly = h - t * h;
            return (
              <text
                key={t}
                x={w + 20 + legendWidth + 6}
                y={ly}
                dominantBaseline="middle"
                fill={LABEL_COLOR}
                fontSize={9}
              >
                {val}
              </text>
            );
          })}
        </g>
      </svg>

      {/* Infobulle React-driven */}
      {hovered && (
        <div
          className="pointer-events-none absolute z-50 rounded-md border border-cyan-500/20 bg-space-dark/95 px-3 py-2 shadow-xl backdrop-blur-sm"
          style={{
            left: hovered.x,
            top: hovered.y,
            fontFamily: "JetBrains Mono, monospace",
            transition: "opacity 0.15s ease",
          }}
        >
          <div className="text-xs font-semibold" style={{ color: CYAN }}>
            {hovered.cell.count} events
          </div>
          <div className="text-xs" style={{ color: LABEL_COLOR }}>
            {DAYS[hovered.cell.day_of_week]} {HOURS[hovered.cell.hour]}
          </div>
        </div>
      )}

      {/* Animation CSS pour le fade-in echelonne */}
      <style>{`
        @keyframes heatmapFadeIn {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
      `}</style>
    </div>
  );
}
