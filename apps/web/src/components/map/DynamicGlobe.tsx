"use client";

import dynamic from "next/dynamic";

/** Dynamic import of GlobeView (no SSR - requires WebGL / DOM). */
const GlobeView = dynamic(() => import("./GlobeView").then((m) => m.default), {
  ssr: false,
  loading: () => (
    <div className="flex h-full flex-col items-center justify-center gap-3">
      <svg
        className="h-8 w-8 animate-spin text-cyan-glow/50"
        fill="none"
        viewBox="0 0 24 24"
      >
        <circle
          className="opacity-25"
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          strokeWidth="4"
        />
        <path
          className="opacity-75"
          fill="currentColor"
          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
        />
      </svg>
      <p className="hud-label animate-pulse">INITIALIZING GLOBE...</p>
    </div>
  ),
});

export { GlobeView as DynamicGlobe };
