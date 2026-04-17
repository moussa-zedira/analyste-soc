import * as React from "react";

const BASE_INPUT =
  "w-full rounded border border-cyan-glow/25 bg-black/50 px-2.5 py-1.5 text-cyan-glow placeholder:text-cyan-glow/30 transition-colors focus:border-cyan-glow/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-glow/40 disabled:opacity-50";

export interface HudFieldProps {
  label?: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export function HudField({ label, hint, error, children, className = "" }: HudFieldProps) {
  return (
    <label className={`flex flex-col gap-1 text-[10px] ${className}`}>
      {label && (
        <span className="uppercase tracking-widest text-cyan-glow/60">{label}</span>
      )}
      {children}
      {hint && !error && <span className="text-cyan-glow/40">{hint}</span>}
      {error && <span className="text-neon-pink">{error}</span>}
    </label>
  );
}

export interface HudInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  mono?: boolean;
}

export const HudInput = React.forwardRef<HTMLInputElement, HudInputProps>(
  function HudInput({ className = "", mono = false, ...rest }, ref) {
    return (
      <input
        ref={ref}
        className={`${BASE_INPUT} ${mono ? "font-mono" : ""} ${className}`}
        {...rest}
      />
    );
  }
);

export interface HudTextareaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  mono?: boolean;
}

export const HudTextarea = React.forwardRef<HTMLTextAreaElement, HudTextareaProps>(
  function HudTextarea({ className = "", mono = true, ...rest }, ref) {
    return (
      <textarea
        ref={ref}
        className={`${BASE_INPUT} resize-y ${mono ? "font-mono" : ""} ${className}`}
        {...rest}
      />
    );
  }
);

export interface HudSelectProps
  extends React.SelectHTMLAttributes<HTMLSelectElement> {}

export const HudSelect = React.forwardRef<HTMLSelectElement, HudSelectProps>(
  function HudSelect({ className = "", children, ...rest }, ref) {
    return (
      <select ref={ref} className={`${BASE_INPUT} ${className}`} {...rest}>
        {children}
      </select>
    );
  }
);
