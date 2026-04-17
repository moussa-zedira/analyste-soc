import * as React from "react";

type Tone =
  | "neutral"
  | "cyan"
  | "matrix"
  | "alert"
  | "warn"
  | "info"
  | "purple"
  | "tp"
  | "fp"
  | "review"
  | "critical"
  | "high"
  | "medium"
  | "low";

const TONE_CLS: Record<Tone, string> = {
  neutral: "border-cyan-glow/30 bg-cyan-glow/5 text-cyan-glow/80",
  cyan: "border-cyan-glow/40 bg-cyan-glow/10 text-cyan-glow",
  matrix: "border-matrix-green/40 bg-matrix-green/10 text-matrix-green",
  alert: "border-neon-pink/40 bg-neon-pink/10 text-neon-pink",
  warn: "border-neon-orange/40 bg-neon-orange/10 text-neon-orange",
  info: "border-neon-blue/40 bg-neon-blue/10 text-neon-blue",
  purple: "border-neon-purple/40 bg-neon-purple/10 text-neon-purple",
  tp: "border-neon-pink/40 bg-neon-pink/10 text-neon-pink",
  fp: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  review: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
  critical: "border-red-500/45 bg-red-500/10 text-red-300",
  high: "border-orange-500/45 bg-orange-500/10 text-orange-300",
  medium: "border-yellow-500/45 bg-yellow-500/10 text-yellow-300",
  low: "border-blue-500/45 bg-blue-500/10 text-blue-300",
};

export interface HudBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone?: Tone;
  glow?: boolean;
  mono?: boolean;
}

export function HudBadge({
  tone = "neutral",
  glow = false,
  mono = false,
  className = "",
  children,
  ...rest
}: HudBadgeProps) {
  const cls = [
    "inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] uppercase tracking-widest",
    mono ? "font-mono normal-case tracking-wider" : "",
    TONE_CLS[tone],
    glow ? `shadow-[0_0_8px_currentColor]` : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <span className={cls} {...rest}>
      {children}
    </span>
  );
}
