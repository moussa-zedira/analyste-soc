"use client";

import { useEffect, useRef, useState } from "react";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
} from "recharts";

/**
 * Carte KPI premium avec compteur anime, sparkline optionnelle
 * et effet de pulsation lumineuse lors des changements de valeur.
 */
export function Card({
  title,
  value,
  subtitle,
  accent,
  loading,
  trend,
  sparkData,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  accent?: string;
  loading?: boolean;
  trend?: "up" | "down" | "neutral";
  sparkData?: number[];
}) {
  /* ── Compteur anime (de 0 a la valeur cible) ── */
  const [displayValue, setDisplayValue] = useState<string | number>(0);
  const rafRef = useRef<number | null>(null);
  const prevValueRef = useRef<string | number>(value);

  /* ── Pulsation lumineuse lors du changement de valeur ── */
  const [glowPulse, setGlowPulse] = useState(false);

  useEffect(() => {
    if (typeof value === "number") {
      const startVal =
        typeof prevValueRef.current === "number" ? prevValueRef.current : 0;
      const endVal = value;
      const duration = 800; // ms
      const startTime = performance.now();

      const animate = (now: number) => {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Courbe ease-out cubique
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(startVal + (endVal - startVal) * eased);
        setDisplayValue(current);
        if (progress < 1) {
          rafRef.current = requestAnimationFrame(animate);
        }
      };

      rafRef.current = requestAnimationFrame(animate);
    } else {
      setDisplayValue(value);
    }

    // Declencher la pulsation lumineuse si la valeur change
    if (prevValueRef.current !== value) {
      setGlowPulse(true);
      const timeout = setTimeout(() => setGlowPulse(false), 700);
      prevValueRef.current = value;
      return () => {
        clearTimeout(timeout);
        if (rafRef.current) cancelAnimationFrame(rafRef.current);
      };
    }

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [value]);

  /* ── Donnees formatees pour la sparkline Recharts ── */
  const chartData = sparkData?.map((v, i) => ({ idx: i, v }));

  /* ── Identifiant unique pour le gradient SVG ── */
  const gradientId = `spark-grad-${title.replace(/\s+/g, "-").toLowerCase()}`;

  if (loading) {
    return (
      <div className="glass-panel hud-corners p-5">
        <div className="skeleton h-4 w-24" />
        <div className="skeleton mt-3 h-9 w-20" />
        <div className="skeleton mt-2 h-3 w-40" />
      </div>
    );
  }

  return (
    <div
      className="glass-panel hud-corners group relative p-5 transition-all duration-300 hover:shadow-cyan-md"
      style={{
        /* Bordure gradient subtile au survol via box-shadow inset */
        backgroundClip: "padding-box",
      }}
    >
      {/* Bordure gradient au survol */}
      <div
        className="pointer-events-none absolute inset-0 rounded-lg opacity-0 transition-opacity duration-500 group-hover:opacity-100"
        style={{
          background:
            "linear-gradient(135deg, rgba(0,229,255,0.25), rgba(0,229,255,0.05) 50%, rgba(0,229,255,0.15))",
          mask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
          maskComposite: "exclude",
          WebkitMaskComposite: "xor",
          padding: "1px",
          borderRadius: "inherit",
        }}
      />

      {/* Ligne de scan au survol */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden rounded-lg opacity-0 transition-opacity duration-500 group-hover:opacity-100">
        <div className="absolute top-0 left-0 right-0 h-px animate-scan-line bg-cyan-glow-line" />
      </div>

      <div className="relative">
        <p className="hud-label">{title}</p>
        <div className="mt-2 flex items-baseline gap-2">
          <p
            className={`text-3xl font-bold tracking-tight transition-all duration-300 ${
              accent ?? "glow-text"
            } ${glowPulse ? "scale-105 brightness-150" : ""}`}
            style={{
              textShadow: glowPulse
                ? "0 0 16px rgba(0, 229, 255, 0.6), 0 0 32px rgba(0, 229, 255, 0.3)"
                : accent
                  ? "0 0 8px rgba(0, 229, 255, 0.3)"
                  : undefined,
              transition: "text-shadow 0.3s ease, transform 0.3s ease",
            }}
          >
            {displayValue}
          </p>
          {trend && trend !== "neutral" && (
            <span
              className={`flex items-center text-xs font-semibold ${
                trend === "up" ? "text-red-400" : "text-green-400"
              }`}
            >
              <svg
                className={`h-3.5 w-3.5 ${trend === "down" ? "rotate-180" : ""}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2.5}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M4.5 15.75l7.5-7.5 7.5 7.5"
                />
              </svg>
            </span>
          )}
        </div>

        {subtitle && (
          <p className="mt-1.5 text-[11px] tracking-wide text-gray-500">
            {subtitle}
          </p>
        )}

        {/* ── Sparkline Recharts (si des donnees sont fournies) ── */}
        {chartData && chartData.length > 0 && (
          <div className="mt-3 -mx-1">
            <ResponsiveContainer width="100%" height={40}>
              <AreaChart
                data={chartData}
                margin={{ top: 0, right: 0, bottom: 0, left: 0 }}
              >
                <defs>
                  <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#00E5FF" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <Area
                  type="monotone"
                  dataKey="v"
                  stroke="#00E5FF"
                  strokeWidth={1.5}
                  fill={`url(#${gradientId})`}
                  dot={false}
                  isAnimationActive={true}
                  animationDuration={800}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}
