import * as React from "react";

type Variant = "primary" | "secondary" | "danger" | "ghost" | "matrix";
type Size = "sm" | "md" | "lg";

const VARIANT: Record<Variant, string> = {
  primary:
    "border-cyan-glow/40 bg-cyan-glow/10 text-cyan-glow hover:bg-cyan-glow/20 hover:shadow-cyan-md",
  secondary:
    "border-cyan-glow/20 bg-black/40 text-cyan-glow/80 hover:border-cyan-glow/40 hover:text-cyan-glow",
  danger:
    "border-neon-pink/45 bg-neon-pink/10 text-neon-pink hover:bg-neon-pink/20 hover:shadow-alert-glow",
  ghost:
    "border-transparent bg-transparent text-cyan-glow/70 hover:text-cyan-glow hover:bg-cyan-glow/5",
  matrix:
    "border-matrix-green/45 bg-matrix-green/10 text-matrix-green hover:bg-matrix-green/20 hover:shadow-matrix-glow",
};

const SIZE: Record<Size, string> = {
  sm: "px-2 py-1 text-[10px]",
  md: "px-3 py-2 text-[11px]",
  lg: "px-4 py-2.5 text-xs",
};

export interface HudButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  block?: boolean;
}

export function HudButton({
  variant = "primary",
  size = "md",
  loading = false,
  block = false,
  className = "",
  disabled,
  children,
  ...rest
}: HudButtonProps) {
  const cls = [
    "inline-flex items-center justify-center gap-2 rounded border font-bold uppercase tracking-widest transition-all duration-150",
    "disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer",
    "focus-visible:ring-2 focus-visible:ring-cyan-glow/60 focus-visible:ring-offset-2 focus-visible:ring-offset-space-deep",
    VARIANT[variant],
    SIZE[size],
    block ? "w-full" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button className={cls} disabled={disabled || loading} {...rest}>
      {loading && (
        <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
      )}
      {children}
    </button>
  );
}
