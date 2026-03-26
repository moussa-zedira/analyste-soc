"use client";

import { useEffect, useRef, useState } from "react";

interface Blip {
  id: string;
  angle: number;
  distance: number;
  severity: "low" | "medium" | "high" | "critical";
  label?: string;
}

interface Props {
  size?: number;
  blips?: Blip[];
  className?: string;
}

const SEVERITY_COLORS = {
  low: "#00E5FF",
  medium: "#EAB308",
  high: "#F97316",
  critical: "#EF4444",
};

const SWEEP_DURATION = 4000; // ms for one full rotation
const SWEEP_CONE_ANGLE = 30; // degrees

function generateDemoBlips(): Blip[] {
  return Array.from({ length: 8 }, (_, i) => ({
    id: `blip-${i}`,
    angle: Math.random() * 360,
    distance: Math.random() * 0.85 + 0.1,
    severity: (["low", "medium", "high", "critical"] as const)[
      Math.floor(Math.random() * 4)
    ],
  }));
}

export function RadarSVG({ size = 280, blips, className = "" }: Props) {
  const [activeBlips, setActiveBlips] = useState<Blip[]>(
    blips ?? generateDemoBlips,
  );
  const [sweepAngle, setSweepAngle] = useState(0);
  const sweepRef = useRef<number | null>(null);
  const startTimeRef = useRef(Date.now());

  const center = size / 2;
  const radius = size / 2 - 16;
  const rings = [0.25, 0.5, 0.75, 1];

  // Track sweep angle in JS (synced to CSS animation cycle)
  useEffect(() => {
    startTimeRef.current = Date.now();
    function tick() {
      const elapsed = Date.now() - startTimeRef.current;
      setSweepAngle((elapsed / SWEEP_DURATION) * 360 % 360);
      sweepRef.current = requestAnimationFrame(tick);
    }
    sweepRef.current = requestAnimationFrame(tick);
    return () => {
      if (sweepRef.current) cancelAnimationFrame(sweepRef.current);
    };
  }, []);

  // Regenerate demo blips periodically
  useEffect(() => {
    if (blips) return;
    const interval = setInterval(() => {
      setActiveBlips((prev) => {
        const updated = [...prev];
        const idx = Math.floor(Math.random() * updated.length);
        updated[idx] = {
          ...updated[idx],
          angle: updated[idx].angle + (Math.random() * 20 - 10),
          distance: Math.min(
            0.95,
            Math.max(
              0.1,
              updated[idx].distance + (Math.random() * 0.1 - 0.05),
            ),
          ),
        };
        return updated;
      });
    }, 2000);
    return () => clearInterval(interval);
  }, [blips]);

  // Sweep cone path (reusable for trails)
  const sweepPath = `M ${center} ${center} L ${center} ${center - radius} A ${radius} ${radius} 0 0 1 ${center + radius * Math.sin((Math.PI * SWEEP_CONE_ANGLE) / 180)} ${center - radius * Math.cos((Math.PI * SWEEP_CONE_ANGLE) / 180)} Z`;

  return (
    <div className={`relative ${className}`}>
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="drop-shadow-lg"
      >
        <defs>
          <linearGradient id="sweep-gradient" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#00E5FF" stopOpacity="0" />
            <stop offset="100%" stopColor="#00E5FF" stopOpacity="0.3" />
          </linearGradient>

          <filter id="blip-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          <filter id="scan-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Background circle */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="rgba(6, 19, 32, 0.8)"
          stroke="rgba(0, 229, 255, 0.1)"
          strokeWidth="1"
        />

        {/* Concentric rings */}
        {rings.map((ring, i) => (
          <circle
            key={i}
            cx={center}
            cy={center}
            r={radius * ring}
            fill="none"
            stroke="rgba(0, 229, 255, 0.12)"
            strokeWidth="1"
            strokeDasharray={i < 3 ? "2 4" : "none"}
          />
        ))}

        {/* Tick marks around outer ring */}
        {Array.from({ length: 72 }, (_, i) => {
          const angleDeg = i * 5;
          const angleRad = (angleDeg * Math.PI) / 180;
          const isMajor = angleDeg % 30 === 0;
          const innerR = radius - (isMajor ? 8 : 4);
          const outerR = radius;
          return (
            <line
              key={`tick-${i}`}
              x1={center + Math.sin(angleRad) * innerR}
              y1={center - Math.cos(angleRad) * innerR}
              x2={center + Math.sin(angleRad) * outerR}
              y2={center - Math.cos(angleRad) * outerR}
              stroke={`rgba(0, 229, 255, ${isMajor ? 0.3 : 0.12})`}
              strokeWidth={isMajor ? 1.5 : 0.5}
            />
          );
        })}

        {/* Distance labels */}
        {[0.25, 0.5, 0.75].map((ring) => (
          <text
            key={`dist-${ring}`}
            x={center + radius * ring * 0.707 + 4}
            y={center - radius * ring * 0.707 - 2}
            fill="rgba(0, 229, 255, 0.2)"
            fontSize="7"
            fontFamily="JetBrains Mono, monospace"
          >
            {Math.round(ring * 100)}%
          </text>
        ))}

        {/* Cross hairs */}
        <line
          x1={center}
          y1={center - radius}
          x2={center}
          y2={center + radius}
          stroke="rgba(0, 229, 255, 0.08)"
          strokeWidth="1"
        />
        <line
          x1={center - radius}
          y1={center}
          x2={center + radius}
          y2={center}
          stroke="rgba(0, 229, 255, 0.08)"
          strokeWidth="1"
        />

        {/* Diagonal cross hairs */}
        <line
          x1={center - radius * 0.707}
          y1={center - radius * 0.707}
          x2={center + radius * 0.707}
          y2={center + radius * 0.707}
          stroke="rgba(0, 229, 255, 0.05)"
          strokeWidth="1"
        />
        <line
          x1={center + radius * 0.707}
          y1={center - radius * 0.707}
          x2={center - radius * 0.707}
          y2={center + radius * 0.707}
          stroke="rgba(0, 229, 255, 0.05)"
          strokeWidth="1"
        />

        {/* Rotating sweep with trails */}
        <g
          style={{
            transformOrigin: `${center}px ${center}px`,
            transform: `rotate(${sweepAngle}deg)`,
          }}
        >
          {/* Trailing sweep cones */}
          {[3, 2, 1].map((trailIndex) => (
            <path
              key={`trail-${trailIndex}`}
              d={sweepPath}
              fill="url(#sweep-gradient)"
              opacity={0.12 - trailIndex * 0.03}
              transform={`rotate(${-trailIndex * 10} ${center} ${center})`}
            />
          ))}

          {/* Main sweep cone */}
          <path d={sweepPath} fill="url(#sweep-gradient)" opacity="0.6" />

          {/* Sweep line */}
          <line
            x1={center}
            y1={center}
            x2={center}
            y2={center - radius}
            stroke="#00E5FF"
            strokeWidth="1.5"
            filter="url(#scan-glow)"
            opacity="0.8"
          />
        </g>

        {/* Blips */}
        {activeBlips.map((blip) => {
          const rad = (blip.angle * Math.PI) / 180;
          const bx = center + Math.sin(rad) * radius * blip.distance;
          const by = center - Math.cos(rad) * radius * blip.distance;
          const color = SEVERITY_COLORS[blip.severity];

          // Check if sweep just passed this blip
          const angleDiff =
            ((sweepAngle - blip.angle) % 360 + 360) % 360;
          const justSwept = angleDiff >= 0 && angleDiff < 40;
          const pulseOpacity = justSwept
            ? 0.6 * (1 - angleDiff / 40)
            : 0;

          return (
            <g key={blip.id}>
              {/* Sweep pulse ring */}
              {justSwept && (
                <circle
                  cx={bx}
                  cy={by}
                  r={8 + angleDiff * 0.3}
                  fill="none"
                  stroke={color}
                  strokeWidth="1"
                  opacity={pulseOpacity}
                />
              )}

              {/* Ping ring */}
              <circle
                cx={bx}
                cy={by}
                r="4"
                fill="none"
                stroke={color}
                strokeWidth="1"
                opacity="0.4"
                style={{
                  animation: "blip-ping 1.5s ease-out infinite",
                  transformOrigin: `${bx}px ${by}px`,
                }}
              />
              {/* Blip dot */}
              <circle
                cx={bx}
                cy={by}
                r="3"
                fill={color}
                filter="url(#blip-glow)"
                opacity={justSwept ? 1 : 0.9}
              />
            </g>
          );
        })}

        {/* Center dot */}
        <circle
          cx={center}
          cy={center}
          r="3"
          fill="#00E5FF"
          filter="url(#blip-glow)"
        />
        <circle
          cx={center}
          cy={center}
          r="6"
          fill="none"
          stroke="#00E5FF"
          strokeWidth="1"
          opacity="0.3"
        />

        {/* Cardinal labels */}
        {[
          { label: "N", x: center, y: center - radius - 6 },
          { label: "S", x: center, y: center + radius + 12 },
          { label: "E", x: center + radius + 10, y: center + 4 },
          { label: "W", x: center - radius - 10, y: center + 4 },
        ].map(({ label, x, y }) => (
          <text
            key={label}
            x={x}
            y={y}
            textAnchor="middle"
            fill="rgba(0, 229, 255, 0.4)"
            fontSize="9"
            fontFamily="Orbitron, sans-serif"
            fontWeight="600"
          >
            {label}
          </text>
        ))}
      </svg>

      {/* Legend */}
      <div className="mt-3 flex items-center justify-center gap-4">
        {(["low", "medium", "high", "critical"] as const).map((sev) => (
          <div key={sev} className="flex items-center gap-1.5">
            <div
              className="h-2 w-2 rounded-full"
              style={{
                backgroundColor: SEVERITY_COLORS[sev],
                boxShadow: `0 0 6px ${SEVERITY_COLORS[sev]}40`,
              }}
            />
            <span className="text-[10px] uppercase tracking-wider text-gray-500">
              {sev}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
