"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";

const BOOT_LINES = [
  { text: "> CYBERDEF SYSTEM v2.0", delay: 200 },
  { text: "> Initializing kernel modules...", status: "OK", delay: 400 },
  { text: "> Loading threat intelligence DB...", status: "OK", delay: 350 },
  { text: "> Connecting to SIEM backbone...", status: "OK", delay: 500 },
  { text: "> Mounting detection engines...", status: "OK", delay: 300 },
  { text: "> Calibrating ML models...", status: "OK", delay: 450 },
  { text: "> Establishing secure channels...", status: "OK", delay: 350 },
  { text: "> Synchronizing threat feeds...", status: "OK", delay: 300 },
  { text: "> SYSTEM READY", delay: 600 },
];

const SESSION_KEY = "cyberdef_booted";

export function BootScreen({ children }: { children: React.ReactNode }) {
  const [booted, setBooted] = useState(false);
  const [skipped, setSkipped] = useState(false);
  const [visibleLines, setVisibleLines] = useState(0);
  const [showStatus, setShowStatus] = useState<boolean[]>([]);
  const [exiting, setExiting] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined" && sessionStorage.getItem(SESSION_KEY)) {
      setSkipped(true);
      setBooted(true);
    }
  }, []);

  useEffect(() => {
    if (skipped) return;

    let timeout: NodeJS.Timeout;
    let lineIndex = 0;

    function showNext() {
      if (lineIndex >= BOOT_LINES.length) {
        timeout = setTimeout(() => {
          setExiting(true);
          setTimeout(() => {
            sessionStorage.setItem(SESSION_KEY, "1");
            setBooted(true);
          }, 800);
        }, 500);
        return;
      }

      setVisibleLines(lineIndex + 1);
      const line = BOOT_LINES[lineIndex];

      if (line.status) {
        timeout = setTimeout(() => {
          setShowStatus((prev) => {
            const next = [...prev];
            next[lineIndex] = true;
            return next;
          });
          lineIndex++;
          timeout = setTimeout(showNext, 150);
        }, line.delay);
      } else {
        lineIndex++;
        timeout = setTimeout(showNext, line.delay);
      }
    }

    timeout = setTimeout(showNext, 500);
    return () => clearTimeout(timeout);
  }, [skipped]);

  const skip = useCallback(() => {
    sessionStorage.setItem(SESSION_KEY, "1");
    setBooted(true);
  }, []);

  const progress = Math.round((visibleLines / BOOT_LINES.length) * 100);

  if (booted) return <>{children}</>;

  return (
    <AnimatePresence>
      {!booted && (
        <motion.div
          initial={{ opacity: 1 }}
          animate={exiting ? { opacity: 0, y: -40 } : { opacity: 1 }}
          transition={{ duration: 0.8, ease: "easeInOut" }}
          className="fixed inset-0 z-[9999] bg-black flex flex-col items-center justify-center overflow-hidden"
          onClick={skip}
        >
          {/* Scanline overlay */}
          <div
            className="absolute inset-0 pointer-events-none opacity-[0.03]"
            style={{
              backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,229,255,0.1) 2px, rgba(0,229,255,0.1) 4px)",
            }}
          />

          {/* Grid overlay */}
          <div
            className="absolute inset-0 pointer-events-none opacity-[0.02]"
            style={{
              backgroundImage:
                "linear-gradient(rgba(0,229,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,255,0.1) 1px, transparent 1px)",
              backgroundSize: "40px 40px",
            }}
          />

          {/* Logo */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6 }}
            className="mb-8"
          >
            <div className="relative w-16 h-16 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-cyan-glow/30 animate-pulse-glow" />
              <svg viewBox="0 0 60 60" className="w-12 h-12">
                <polygon
                  points="30,2 56,17 56,43 30,58 4,43 4,17"
                  fill="none"
                  stroke="#00E5FF"
                  strokeWidth="1.5"
                  opacity="0.6"
                />
                <text
                  x="30"
                  y="35"
                  textAnchor="middle"
                  fill="#00E5FF"
                  fontSize="14"
                  fontFamily="Orbitron, sans-serif"
                  fontWeight="700"
                >
                  CD
                </text>
              </svg>
            </div>
          </motion.div>

          {/* Boot lines */}
          <div className="w-full max-w-lg px-8 font-mono text-sm space-y-1">
            {BOOT_LINES.slice(0, visibleLines).map((line, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.15 }}
                className="flex items-center justify-between"
              >
                <span className={i === BOOT_LINES.length - 1 && visibleLines === BOOT_LINES.length ? "text-cyan-glow font-bold" : "text-cyan-dim/80"}>
                  {line.text}
                </span>
                {line.status && showStatus[i] && (
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="text-green-400 font-bold text-xs ml-4"
                  >
                    [{line.status}]
                  </motion.span>
                )}
              </motion.div>
            ))}
          </div>

          {/* Progress bar */}
          <div className="w-full max-w-lg px-8 mt-8">
            <div className="h-0.5 bg-cyan-faint/20 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-cyan-glow/60 to-cyan-glow rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>
            <div className="flex justify-between mt-2">
              <span className="text-[10px] text-cyan-muted/50 font-mono">{progress}%</span>
              <span className="text-[10px] text-cyan-muted/30 font-mono">CLICK TO SKIP</span>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
