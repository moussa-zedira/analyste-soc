import * as React from "react";

type Level = 1 | 2 | 3;

export interface HudHeadingProps extends React.HTMLAttributes<HTMLHeadingElement> {
  level?: Level;
  subtitle?: React.ReactNode;
  glitch?: boolean;
  caret?: boolean;
}

const SIZE: Record<Level, string> = {
  1: "text-xl md:text-2xl",
  2: "text-lg",
  3: "text-sm",
};

export function HudHeading({
  level = 1,
  subtitle,
  glitch = false,
  caret = false,
  className = "",
  children,
  ...rest
}: HudHeadingProps) {
  const Tag = `h${level}` as React.ElementType;
  const headingCls = [
    "hud-heading font-bold tracking-widest text-cyan-glow",
    SIZE[level],
    glitch ? "glitch-text" : "",
    caret ? "terminal-caret" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <div>
      <Tag
        className={headingCls}
        style={{ fontFamily: "Orbitron, sans-serif" }}
        {...(rest as any)}
      >
        {children}
      </Tag>
      {subtitle && (
        <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/40">
          {subtitle}
        </p>
      )}
    </div>
  );
}
