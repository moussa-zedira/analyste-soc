import * as React from "react";

type Variant = "glass" | "deep" | "holographic";
type Tone = "default" | "alert" | "warn" | "matrix";

const VARIANT: Record<Variant, string> = {
  glass: "glass-panel",
  deep: "panel-deep",
  holographic: "holographic-border holographic-border-anim rounded-lg",
};

const TONE: Record<Tone, string> = {
  default: "",
  alert: "shadow-alert-glow border-neon-pink/40",
  warn: "shadow-warn-glow border-neon-orange/40",
  matrix: "shadow-matrix-glow border-matrix-green/40",
};

export interface HudCardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: Variant;
  tone?: Tone;
  corners?: boolean | "lg";
  scanlines?: boolean;
  as?: React.ElementType;
}

export function HudCard({
  variant = "glass",
  tone = "default",
  corners = false,
  scanlines = false,
  as: Tag = "div",
  className = "",
  children,
  ...rest
}: HudCardProps) {
  const cornerCls = corners === "lg" ? "hud-corners-lg" : corners ? "hud-corners" : "";
  const cls = [
    VARIANT[variant],
    TONE[tone],
    cornerCls,
    scanlines ? "scanlines" : "",
    "relative",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <Tag className={cls} {...(rest as any)}>
      {children}
    </Tag>
  );
}
