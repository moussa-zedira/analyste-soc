"use client";

import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from "react";
import {
  motion,
  useMotionValue,
  useSpring,
  useTransform,
  AnimatePresence,
  useInView,
} from "framer-motion";

/* ========================================================================== */
/*  AnimatedCounter                                                           */
/*  Number that counts up from 0 to value with easing                         */
/* ========================================================================== */

export interface AnimatedCounterProps {
  value: number;
  duration?: number;
  decimals?: number;
  prefix?: string;
  suffix?: string;
  className?: string;
}

export function AnimatedCounter({
  value,
  duration = 1.2,
  decimals = 0,
  prefix = "",
  suffix = "",
  className = "",
}: AnimatedCounterProps) {
  const motionVal = useMotionValue(0);
  const springVal = useSpring(motionVal, { duration: duration * 1000, bounce: 0 });
  const [display, setDisplay] = useState("0");

  useEffect(() => {
    motionVal.set(value);
  }, [value, motionVal]);

  useEffect(() => {
    const unsub = springVal.on("change", (v) => {
      setDisplay(v.toFixed(decimals));
    });
    return unsub;
  }, [springVal, decimals]);

  return (
    <span className={className}>
      {prefix}
      {display}
      {suffix}
    </span>
  );
}

/* ========================================================================== */
/*  PulseOnUpdate                                                             */
/*  Wrapper that pulses cyan glow when children change                        */
/* ========================================================================== */

export interface PulseOnUpdateProps {
  children: React.ReactNode;
  watchValue: unknown;
  className?: string;
}

export function PulseOnUpdate({ children, watchValue, className = "" }: PulseOnUpdateProps) {
  const [pulse, setPulse] = useState(false);
  const prevRef = useRef(watchValue);

  useEffect(() => {
    if (prevRef.current !== watchValue) {
      setPulse(true);
      prevRef.current = watchValue;
      const t = setTimeout(() => setPulse(false), 700);
      return () => clearTimeout(t);
    }
  }, [watchValue]);

  return (
    <div
      className={`transition-shadow duration-700 rounded ${
        pulse ? "shadow-[0_0_18px_rgba(0,229,255,0.45)]" : "shadow-none"
      } ${className}`}
    >
      {children}
    </div>
  );
}

/* ========================================================================== */
/*  RippleButton                                                              */
/*  Button with material-design ripple effect in cyan                         */
/* ========================================================================== */

export interface RippleButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
}

interface Ripple {
  id: number;
  x: number;
  y: number;
  size: number;
}

export function RippleButton({ children, className = "", onClick, ...props }: RippleButtonProps) {
  const [ripples, setRipples] = useState<Ripple[]>([]);
  const nextId = useRef(0);

  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLButtonElement>) => {
      const rect = e.currentTarget.getBoundingClientRect();
      const size = Math.max(rect.width, rect.height) * 2;
      const x = e.clientX - rect.left - size / 2;
      const y = e.clientY - rect.top - size / 2;
      const id = nextId.current++;
      setRipples((prev) => [...prev, { id, x, y, size }]);
      setTimeout(() => {
        setRipples((prev) => prev.filter((r) => r.id !== id));
      }, 600);
      onClick?.(e);
    },
    [onClick],
  );

  return (
    <button
      {...props}
      onClick={handleClick}
      className={`relative overflow-hidden ${className}`}
    >
      {children}
      {ripples.map((r) => (
        <motion.span
          key={r.id}
          initial={{ opacity: 0.5, scale: 0 }}
          animate={{ opacity: 0, scale: 1 }}
          transition={{ duration: 0.6, ease: "easeOut" }}
          className="absolute rounded-full bg-cyan-glow/30 pointer-events-none"
          style={{ left: r.x, top: r.y, width: r.size, height: r.size }}
        />
      ))}
    </button>
  );
}

/* ========================================================================== */
/*  HoverCard                                                                 */
/*  Card that tilts slightly on mouse hover (3D perspective transform)        */
/* ========================================================================== */

export interface HoverCardProps {
  children: React.ReactNode;
  className?: string;
  tiltDeg?: number;
}

export function HoverCard({ children, className = "", tiltDeg = 6 }: HoverCardProps) {
  const ref = useRef<HTMLDivElement>(null);
  const rotateX = useMotionValue(0);
  const rotateY = useMotionValue(0);
  const smoothX = useSpring(rotateX, { stiffness: 200, damping: 20 });
  const smoothY = useSpring(rotateY, { stiffness: 200, damping: 20 });

  const handleMove = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (!ref.current) return;
      const rect = ref.current.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const px = (e.clientX - cx) / (rect.width / 2);
      const py = (e.clientY - cy) / (rect.height / 2);
      rotateY.set(px * tiltDeg);
      rotateX.set(-py * tiltDeg);
    },
    [rotateX, rotateY, tiltDeg],
  );

  const handleLeave = useCallback(() => {
    rotateX.set(0);
    rotateY.set(0);
  }, [rotateX, rotateY]);

  return (
    <motion.div
      ref={ref}
      onMouseMove={handleMove}
      onMouseLeave={handleLeave}
      style={{
        perspective: 800,
        rotateX: smoothX,
        rotateY: smoothY,
        transformStyle: "preserve-3d",
      }}
      className={`will-change-transform ${className}`}
    >
      {children}
    </motion.div>
  );
}

/* ========================================================================== */
/*  ProgressRing                                                              */
/*  Circular SVG progress indicator with animation                            */
/* ========================================================================== */

export interface ProgressRingProps {
  value: number;       // 0-100
  size?: number;
  strokeWidth?: number;
  color?: string;
  trackColor?: string;
  className?: string;
  children?: React.ReactNode;
}

export function ProgressRing({
  value,
  size = 80,
  strokeWidth = 6,
  color = "#00E5FF",
  trackColor = "rgba(0,229,255,0.1)",
  className = "",
  children,
}: ProgressRingProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(Math.max(value, 0), 100) / 100) * circumference;

  return (
    <div className={`relative inline-flex items-center justify-center ${className}`} style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={trackColor}
          strokeWidth={strokeWidth}
        />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1, ease: "easeOut" }}
        />
      </svg>
      {children && (
        <div className="absolute inset-0 flex items-center justify-center">
          {children}
        </div>
      )}
    </div>
  );
}

/* ========================================================================== */
/*  StatusDot                                                                 */
/*  Animated status indicator                                                 */
/* ========================================================================== */

export type StatusDotStatus = "online" | "warning" | "error" | "offline";

export interface StatusDotProps {
  status: StatusDotStatus;
  size?: number;
  className?: string;
  label?: string;
}

const DOT_COLORS: Record<StatusDotStatus, { bg: string; ring: string }> = {
  online: { bg: "bg-emerald-400", ring: "bg-emerald-400/40" },
  warning: { bg: "bg-yellow-400", ring: "bg-yellow-400/40" },
  error: { bg: "bg-red-500", ring: "bg-red-500/40" },
  offline: { bg: "bg-slate-500", ring: "bg-slate-500/0" },
};

export function StatusDot({ status, size = 10, className = "", label }: StatusDotProps) {
  const { bg, ring } = DOT_COLORS[status];
  const animated = status !== "offline";

  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <span className="relative inline-flex" style={{ width: size, height: size }}>
        {animated && (
          <span
            className={`absolute inset-0 rounded-full ${ring} animate-ping`}
            style={{ animationDuration: "1.5s" }}
          />
        )}
        <span className={`relative inline-flex rounded-full ${bg}`} style={{ width: size, height: size }} />
      </span>
      {label && <span className="text-xs text-slate-400">{label}</span>}
    </span>
  );
}

/* ========================================================================== */
/*  TypeWriter                                                                */
/*  Text that types out character by character                                */
/* ========================================================================== */

export interface TypeWriterProps {
  text: string;
  speed?: number;    // ms per character
  className?: string;
  cursor?: boolean;
  onComplete?: () => void;
}

export function TypeWriter({ text, speed = 40, className = "", cursor = true, onComplete }: TypeWriterProps) {
  const [displayed, setDisplayed] = useState("");
  const [done, setDone] = useState(false);

  useEffect(() => {
    setDisplayed("");
    setDone(false);
    let i = 0;
    const interval = setInterval(() => {
      i++;
      setDisplayed(text.slice(0, i));
      if (i >= text.length) {
        clearInterval(interval);
        setDone(true);
        onComplete?.();
      }
    }, speed);
    return () => clearInterval(interval);
  }, [text, speed, onComplete]);

  return (
    <span className={className}>
      {displayed}
      {cursor && !done && (
        <motion.span
          animate={{ opacity: [1, 0] }}
          transition={{ duration: 0.6, repeat: Infinity, repeatType: "reverse" }}
          className="inline-block w-[2px] h-[1em] bg-cyan-glow ml-[1px] align-middle"
        />
      )}
    </span>
  );
}

/* ========================================================================== */
/*  CountBadge                                                                */
/*  Badge that animates number changes (scale bounce)                         */
/* ========================================================================== */

export interface CountBadgeProps {
  count: number;
  className?: string;
}

export function CountBadge({ count, className = "" }: CountBadgeProps) {
  const [key, setKey] = useState(0);
  const prevRef = useRef(count);

  useEffect(() => {
    if (prevRef.current !== count) {
      setKey((k) => k + 1);
      prevRef.current = count;
    }
  }, [count]);

  return (
    <motion.span
      key={key}
      initial={{ scale: 1.4, opacity: 0.6 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: "spring", stiffness: 400, damping: 15 }}
      className={`inline-flex items-center justify-center min-w-[22px] h-[22px] px-1.5 rounded-full text-[10px] font-bold bg-cyan-glow/20 text-cyan-glow border border-cyan-glow/30 ${className}`}
    >
      {count}
    </motion.span>
  );
}

/* ========================================================================== */
/*  SlideReveal                                                               */
/*  Content that reveals on scroll (intersection observer)                    */
/* ========================================================================== */

export interface SlideRevealProps {
  children: React.ReactNode;
  direction?: "up" | "down" | "left" | "right";
  delay?: number;
  className?: string;
}

const SLIDE_OFFSETS = {
  up: { y: 30, x: 0 },
  down: { y: -30, x: 0 },
  left: { x: 30, y: 0 },
  right: { x: -30, y: 0 },
};

export function SlideReveal({ children, direction = "up", delay = 0, className = "" }: SlideRevealProps) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });
  const offset = SLIDE_OFFSETS[direction];

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, x: offset.x, y: offset.y }}
      animate={inView ? { opacity: 1, x: 0, y: 0 } : {}}
      transition={{ duration: 0.5, delay, ease: "easeOut" }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/* ========================================================================== */
/*  GlitchText                                                                */
/*  Text with occasional glitch effect (for headings)                         */
/* ========================================================================== */

export interface GlitchTextProps {
  text: string;
  className?: string;
  interval?: number; // ms between glitches
}

export function GlitchText({ text, className = "", interval = 4000 }: GlitchTextProps) {
  const [glitching, setGlitching] = useState(false);

  useEffect(() => {
    const id = setInterval(() => {
      setGlitching(true);
      setTimeout(() => setGlitching(false), 200);
    }, interval);
    return () => clearInterval(id);
  }, [interval]);

  return (
    <span className={`relative inline-block ${className}`}>
      <span className="relative z-10">{text}</span>
      {glitching && (
        <>
          <span
            className="absolute top-0 left-0 z-20 text-red-500/70"
            style={{ clipPath: "inset(10% 0 60% 0)", transform: "translateX(-2px)" }}
            aria-hidden
          >
            {text}
          </span>
          <span
            className="absolute top-0 left-0 z-20 text-cyan-glow/70"
            style={{ clipPath: "inset(50% 0 10% 0)", transform: "translateX(2px)" }}
            aria-hidden
          >
            {text}
          </span>
        </>
      )}
    </span>
  );
}
