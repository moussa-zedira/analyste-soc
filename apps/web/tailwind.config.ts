import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        space: {
          deep: "#0B1C2D",
          dark: "#061320",
          mid: "#0F2A40",
          light: "#153550",
        },
        cyan: {
          glow: "#00E5FF",
          dim: "#00B8D4",
          muted: "#006B7D",
          faint: "#003845",
        },
        severity: {
          low: "#3B82F6",
          medium: "#EAB308",
          high: "#F97316",
          critical: "#EF4444",
        },
      },
      backgroundImage: {
        "space-radial":
          "radial-gradient(ellipse at 50% 0%, #0F2A40 0%, #0B1C2D 50%, #061320 100%)",
        "space-vignette":
          "radial-gradient(ellipse at center, transparent 0%, #061320 70%)",
        "cyan-glow-line":
          "linear-gradient(90deg, transparent, #00E5FF, transparent)",
      },
      boxShadow: {
        "cyan-sm": "0 0 6px rgba(0, 229, 255, 0.15)",
        "cyan-md": "0 0 12px rgba(0, 229, 255, 0.2)",
        "cyan-lg": "0 0 24px rgba(0, 229, 255, 0.25)",
        "cyan-glow": "0 0 20px rgba(0, 229, 255, 0.3), inset 0 0 20px rgba(0, 229, 255, 0.05)",
        "inner-cyan": "inset 0 0 30px rgba(0, 229, 255, 0.06)",
      },
      animation: {
        "fade-in": "fade-in 0.4s ease-out",
        "slide-up": "slide-up 0.35s ease-out",
        "slide-in": "slide-in 0.3s ease-out",
        "slide-in-right": "slide-in-right 0.3s ease-out",
        "pulse-glow": "pulse-glow 2s ease-in-out infinite",
        "bar-grow": "bar-grow 0.6s ease-out",
        "radar-spin": "radar-spin 4s linear infinite",
        "scan-line": "scan-line 3s ease-in-out infinite",
        "glow-pulse": "glow-pulse 2.5s ease-in-out infinite",
        "float": "float 6s ease-in-out infinite",
        "star-twinkle": "star-twinkle 3s ease-in-out infinite",
        "blip-ping": "blip-ping 1.5s ease-out infinite",
        "hud-reveal": "hud-reveal 0.6s ease-out",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "slide-up": {
          from: { opacity: "0", transform: "translateY(12px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "slide-in": {
          from: { opacity: "0", transform: "translateX(100%)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        "slide-in-right": {
          from: { opacity: "0", transform: "translateX(20px)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        "pulse-glow": {
          "0%, 100%": { boxShadow: "0 0 0 0 rgba(0,229,255,0)" },
          "50%": { boxShadow: "0 0 12px 2px rgba(0,229,255,0.15)" },
        },
        "bar-grow": {
          from: { transform: "scaleY(0)" },
          to: { transform: "scaleY(1)" },
        },
        "radar-spin": {
          from: { transform: "rotate(0deg)" },
          to: { transform: "rotate(360deg)" },
        },
        "scan-line": {
          "0%": { transform: "translateY(-100%)", opacity: "0" },
          "50%": { opacity: "0.6" },
          "100%": { transform: "translateY(400%)", opacity: "0" },
        },
        "glow-pulse": {
          "0%, 100%": { opacity: "0.4" },
          "50%": { opacity: "1" },
        },
        "float": {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-6px)" },
        },
        "star-twinkle": {
          "0%, 100%": { opacity: "0.2" },
          "50%": { opacity: "0.8" },
        },
        "blip-ping": {
          "0%": { transform: "scale(1)", opacity: "1" },
          "100%": { transform: "scale(2.5)", opacity: "0" },
        },
        "hud-reveal": {
          from: { opacity: "0", transform: "scale(0.95)", filter: "blur(4px)" },
          to: { opacity: "1", transform: "scale(1)", filter: "blur(0)" },
        },
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "'Fira Code'", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
