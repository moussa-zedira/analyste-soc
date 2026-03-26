"use client";

import { useCallback, useState } from "react";
import { runMLDetection, getMLModelInfo } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { MLModelInfo, MLDetectResponse } from "@/lib/types";

export function MLStatusCard({ onDetection }: { onDetection?: () => void }) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<MLDetectResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const { data: modelInfo } = useFetchData<MLModelInfo | null>(
    (signal) => getMLModelInfo({ signal }),
    null,
    [refreshKey],
  );

  const handleDetect = useCallback(async () => {
    setRunning(true);
    setResult(null);
    setError(null);
    try {
      const res = await runMLDetection();
      setResult(res);
      setRefreshKey((k) => k + 1);
      onDetection?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "ML detection failed");
    } finally {
      setRunning(false);
    }
  }, [onDetection]);

  const trained = modelInfo?.status === "trained";

  return (
    <div className="glass-panel p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="hud-label">
          ML Detection (Isolation Forest)
        </h2>
        <button
          onClick={handleDetect}
          disabled={running}
          className="group relative overflow-hidden rounded-md border border-purple-500/30 bg-purple-500/10 px-4 py-1.5 text-[10px] font-bold tracking-wider text-purple-400 transition-all hover:bg-purple-500/20 hover:shadow-[0_0_12px_rgba(168,85,247,0.15)] disabled:opacity-50"
        >
          {running ? "RUNNING..." : "RUN ML DETECTION"}
        </button>
      </div>

      {/* Model info boxes */}
      <div className="flex flex-wrap gap-3 text-xs">
        <div className="rounded-md border border-cyan-glow/10 bg-space-mid/50 px-3 py-2">
          <p className="text-[9px] tracking-wider text-gray-600">STATUS</p>
          <p
            className={`font-bold tracking-wider ${
              trained ? "glow-text-sm" : "text-gray-500"
            }`}
          >
            {trained ? "TRAINED" : "NOT TRAINED"}
          </p>
        </div>
        {modelInfo?.n_samples != null && (
          <div className="rounded-md border border-cyan-glow/10 bg-space-mid/50 px-3 py-2">
            <p className="text-[9px] tracking-wider text-gray-600">SAMPLES</p>
            <p className="font-bold text-cyan-dim">{modelInfo.n_samples}</p>
          </div>
        )}
        {modelInfo?.n_features != null && (
          <div className="rounded-md border border-cyan-glow/10 bg-space-mid/50 px-3 py-2">
            <p className="text-[9px] tracking-wider text-gray-600">FEATURES</p>
            <p className="font-bold text-cyan-dim">{modelInfo.n_features}</p>
          </div>
        )}
        {modelInfo?.last_trained && (
          <div className="rounded-md border border-cyan-glow/10 bg-space-mid/50 px-3 py-2">
            <p className="text-[9px] tracking-wider text-gray-600">
              LAST TRAINED
            </p>
            <p className="font-bold text-cyan-dim">
              {new Date(modelInfo.last_trained).toLocaleTimeString()}
            </p>
          </div>
        )}
      </div>

      {/* Result */}
      {result && (
        <div className="mt-3 rounded-md border border-cyan-glow/20 bg-cyan-glow/5 px-3 py-2 text-[11px] tracking-wide text-cyan-glow">
          <span className="mr-1">&#x25C6;</span>
          Analyzed {result.samples_analyzed} IPs — {result.anomalies_detected}{" "}
          anomalies detected, {result.incidents_created} incidents created.
        </div>
      )}
      {error && (
        <div className="mt-3 rounded-md border border-red-500/20 bg-red-500/5 px-3 py-2 text-[11px] tracking-wide text-red-400">
          <span className="mr-1">&#x25B2;</span>
          {error}
        </div>
      )}
    </div>
  );
}
