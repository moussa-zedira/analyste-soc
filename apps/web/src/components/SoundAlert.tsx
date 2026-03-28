"use client";

import { useCallback, useRef, useState } from "react";

type Severity = "critical" | "high" | "medium" | "low" | "info";

const TONE_MAP: Record<Severity, { freqs: number[]; durations: number[]; pattern: number[] }> = {
  critical: { freqs: [880, 0, 880, 0, 880], durations: [120, 80, 120, 80, 200], pattern: [120, 80, 120, 80, 200] },
  high:     { freqs: [660, 0, 660], durations: [150, 100, 200], pattern: [150, 100, 200] },
  medium:   { freqs: [440], durations: [250], pattern: [250] },
  low:      { freqs: [330], durations: [300], pattern: [300] },
  info:     { freqs: [520], durations: [150], pattern: [150] },
};

export function useSoundAlert() {
  const ctxRef = useRef<AudioContext | null>(null);
  const [muted, setMuted] = useState(false);
  const [volume, setVolume] = useState(0.3);

  const getCtx = useCallback(() => {
    if (!ctxRef.current) ctxRef.current = new AudioContext();
    return ctxRef.current;
  }, []);

  const play = useCallback(
    (severity: Severity) => {
      if (muted) return;
      const ctx = getCtx();
      const tone = TONE_MAP[severity] || TONE_MAP.info;
      let offset = ctx.currentTime;

      tone.freqs.forEach((freq, i) => {
        if (freq === 0) {
          offset += tone.durations[i] / 1000;
          return;
        }
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = severity === "critical" ? "square" : severity === "low" ? "sine" : "triangle";
        osc.frequency.value = freq;
        gain.gain.value = volume;
        gain.gain.exponentialRampToValueAtTime(0.001, offset + tone.durations[i] / 1000);
        osc.connect(gain).connect(ctx.destination);
        osc.start(offset);
        osc.stop(offset + tone.durations[i] / 1000);
        offset += tone.durations[i] / 1000;
      });
    },
    [muted, volume, getCtx]
  );

  return { play, muted, setMuted, volume, setVolume };
}

export function SoundToggleButton({ muted, onToggle }: { muted: boolean; onToggle: () => void }) {
  return (
    <button
      onClick={onToggle}
      className="p-1.5 rounded transition-colors hover:bg-cyan-glow/10"
      title={muted ? "Unmute alerts" : "Mute alerts"}
    >
      {muted ? (
        <svg className="w-4 h-4 text-cyan-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M17 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2" />
        </svg>
      ) : (
        <svg className="w-4 h-4 text-cyan-glow" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M15.536 8.464a5 5 0 010 7.072M18.364 5.636a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" />
        </svg>
      )}
    </button>
  );
}
