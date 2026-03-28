"use client";

import { useCallback, useState } from "react";
import { runMLDetection, getMLModelInfo } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { MLModelInfo, MLDetectResponse } from "@/lib/types";

export default function MLWidget({ refreshKey }: { refreshKey: number }) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<MLDetectResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [localKey, setLocalKey] = useState(0);

  const { data: modelInfo, loading } = useFetchData<MLModelInfo | null>(
    (signal) => getMLModelInfo({ signal }),
    null,
    [refreshKey, localKey],
  );

  const handleDetect = useCallback(async () => {
    setRunning(true);
    setResult(null);
    setError(null);
    try {
      const res = await runMLDetection();
      setResult(res);
      setLocalKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "ML detection failed");
    } finally {
      setRunning(false);
    }
  }, []);

  const trained = modelInfo?.status === "trained";

  if (loading) {
    return (
      <div className="space-y-3">
        <div className="skeleton h-4 w-32" />
        <div className="flex gap-2">
          <div className="skeleton h-12 w-24" />
          <div className="skeleton h-12 w-24" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Model status boxes */}
      <div className="flex flex-wrap gap-2">
        <div className="rounded-md border border-cyan-glow/10 bg-space-mid/50 px-3 py-2">
          <p className="text-[8px] tracking-wider text-gray-600">STATUS</p>
          <p className={`text-xs font-bold tracking-wider ${trained ? "glow-text-sm" : "text-gray-500"}`}>
            {trained ? "TRAINED" : "NOT TRAINED"}
          </p>
        </div>
        {modelInfo?.n_samples != null && (
          <div className="rounded-md border border-cyan-glow/10 bg-space-mid/50 px-3 py-2">
            <p className="text-[8px] tracking-wider text-gray-600">SAMPLES</p>
            <p className="text-xs font-bold text-cyan-dim">{modelInfo.n_samples}</p>
          </div>
        )}
        {modelInfo?.n_features != null && (
          <div className="rounded-md border border-cyan-glow/10 bg-space-mid/50 px-3 py-2">
            <p className="text-[8px] tracking-wider text-gray-600">FEATURES</p>
            <p className="text-xs font-bold text-cyan-dim">{modelInfo.n_features}</p>
          </div>
        )}
      </div>

      {/* Run button */}
      <button
        onClick={handleDetect}
        disabled={running}
        className="w-full rounded-md border border-purple-500/30 bg-purple-500/10 px-4 py-1.5 text-[10px] font-bold tracking-wider text-purple-400 transition-all hover:bg-purple-500/20 hover:shadow-[0_0_12px_rgba(168,85,247,0.15)] disabled:opacity-50"
      >
        {running ? "RUNNING..." : "RUN ML DETECTION"}
      </button>

      {/* Result */}
      {result && (
        <div className="rounded-md border border-cyan-glow/20 bg-cyan-glow/5 px-3 py-2 text-[10px] tracking-wide text-cyan-glow">
          <span className="mr-1">&#x25C6;</span>
          {result.samples_analyzed} IPs analyzed - {result.anomalies_detected} anomalies - {result.incidents_created} incidents
        </div>
      )}
      {error && (
        <div className="rounded-md border border-red-500/20 bg-red-500/5 px-3 py-2 text-[10px] tracking-wide text-red-400">
          <span className="mr-1">&#x25B2;</span>
          {error}
        </div>
      )}
    </div>
  );
}
