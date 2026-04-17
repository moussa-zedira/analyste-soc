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
        oled: {
          black: "#000000",
          near: "#0A0A0A",
          panel: "#0D0D0D",
          raised: "#121212",
        },
        cyan: {
          glow: "#00E5FF",
          dim: "#00B8D4",
          muted: "#006B7D",
          faint: "#003845",
        },
        matrix: {
          green: "#00FF41",
          dim: "#00B82E",
          deep: "#003B00",
        },
        neon: {
          pink: "#FF006E",
          magenta: "#FF00FF",
          purple: "#A855F7",
          orange: "#FF9500",
          blue: "#0080FF",
        },
        severity: {
          info: "#0080FF",
          low: "#3B82F6",
          medium: "#EAB308",
          high: "#F97316",
          critical: "#EF4444",
        },
        verdict: {
          tp: "#FF006E",
          fp: "#10B981",
          review: "#FACC15",
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
        "matrix-glow": "0 0 14px rgba(0, 255, 65, 0.35), inset 0 0 18px rgba(0, 255, 65, 0.06)",
        "alert-glow": "0 0 18px rgba(255, 0, 110, 0.4), inset 0 0 22px rgba(255, 0, 110, 0.08)",
        "warn-glow": "0 0 14px rgba(255, 149, 0, 0.35), inset 0 0 18px rgba(255, 149, 0, 0.06)",
        "holographic": "0 0 24px rgba(0,229,255,0.25), 0 0 12px rgba(168,85,247,0.18), inset 0 0 32px rgba(0,229,255,0.05)",
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
        "glitch": "glitch 0.4s steps(2) infinite",
        "ticker": "ticker 30s linear infinite",
        "blink-caret": "blink-caret 1.06s steps(2, start) infinite",
        "holographic-shift": "holographic-shift 6s ease-in-out infinite",
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
        "glitch": {
          "0%, 100%": { transform: "translate(0)", textShadow: "0 0 0 transparent" },
          "20%": { transform: "translate(-1px, 1px)", textShadow: "1px 0 #FF006E, -1px 0 #00E5FF" },
          "40%": { transform: "translate(1px, -1px)", textShadow: "-1px 0 #FF006E, 1px 0 #00E5FF" },
          "60%": { transform: "translate(-1px, 0)", textShadow: "1px 0 #00FF41, -1px 0 #FF00FF" },
        },
        "ticker": {
          from: { transform: "translateX(0)" },
          to: { transform: "translateX(-50%)" },
        },
        "blink-caret": {
          "from, to": { opacity: "0" },
          "50%": { opacity: "1" },
        },
        "holographic-shift": {
          "0%, 100%": { backgroundPosition: "0% 50%" },
          "50%": { backgroundPosition: "100% 50%" },
        },
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "'Fira Code'", "monospace"],
        sans: ["'IBM Plex Sans'", "Inter", "system-ui", "sans-serif"],
        display: ["'Orbitron'", "'IBM Plex Sans'", "sans-serif"],
      },
    },
  },
  plugins: [],
};

export default config;
