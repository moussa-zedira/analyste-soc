"use client";

import { useEffect, useState } from "react";

import { aiRagCorpus, aiRagSearch } from "@/lib/apiClient";
import type { RagSearchResult } from "@/lib/types";

export default function AiRagPage() {
  const [query, setQuery] = useState("ssh brute force admin");
  const [topK, setTopK] = useState(10);
  const [lookback, setLookback] = useState(168);
  const [includeEvents, setIncludeEvents] = useState(true);
  const [includeIncidents, setIncludeIncidents] = useState(true);
  const [corpus, setCorpus] = useState<{ corpus_size: number; by_kind: Record<string, number>; approx_token_count: number } | null>(null);
  const [result, setResult] = useState<RagSearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    aiRagCorpus(lookback).then(setCorpus).catch(() => {});
  }, [lookback]);

  const search = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await aiRagSearch({
        query,
        top_k: topK,
        include_events: includeEvents,
        include_incidents: includeIncidents,
        lookback_hours: lookback,
      });
      setResult(r);
    } catch (e: any) {
      setError(e?.message ?? "search error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow"
            style={{ fontFamily: "Orbitron, sans-serif" }}>
          RAG — Semantic Search on Historical Logs
        </h1>
        <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
          TF-IDF // COSINE SIMILARITY // EVENTS + INCIDENTS CORPUS
        </p>
      </div>

      {corpus && (
        <div className="grid grid-cols-3 gap-3">
          <div className="glass-panel border border-cyan-glow/20 p-3">
            <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60">Corpus size</div>
            <div className="text-2xl font-bold text-cyan-glow">{corpus.corpus_size}</div>
          </div>
          <div className="glass-panel border border-cyan-glow/20 p-3">
            <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60">By kind</div>
            <div className="mt-1 text-xs text-cyan-glow">
              {Object.entries(corpus.by_kind).map(([k, v]) => (
                <span key={k} className="mr-3">{k}: <span className="font-bold">{v}</span></span>
              ))}
            </div>
          </div>
          <div className="glass-panel border border-cyan-glow/20 p-3">
            <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60">Approx tokens</div>
            <div className="text-2xl font-bold text-cyan-glow">{corpus.approx_token_count.toLocaleString()}</div>
          </div>
        </div>
      )}

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-300">{error}</div>
      )}

      <div className="glass-panel border border-cyan-glow/20 p-4 space-y-3">
        <label className="flex flex-col gap-1 text-[10px]">
          <span className="uppercase tracking-widest text-cyan-glow/60">Query</span>
          <input value={query} onChange={(e) => setQuery(e.target.value)}
                 onKeyDown={(e) => { if (e.key === "Enter") search(); }}
                 placeholder="What are you looking for?"
                 className="rounded border border-cyan-glow/30 bg-black/40 px-3 py-2 font-mono text-cyan-glow" />
        </label>
        <div className="grid grid-cols-4 gap-3 text-[10px]">
          <label className="flex flex-col gap-1">
            <span className="uppercase tracking-widest text-cyan-glow/60">Top K</span>
            <input type="number" min={1} max={50} value={topK}
                   onChange={(e) => setTopK(parseInt(e.target.value || "10"))}
                   className="rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-cyan-glow" />
          </label>
          <label className="flex flex-col gap-1">
            <span className="uppercase tracking-widest text-cyan-glow/60">Lookback (h)</span>
            <input type="number" min={1} max={8760} value={lookback}
                   onChange={(e) => setLookback(parseInt(e.target.value || "168"))}
                   className="rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-cyan-glow" />
          </label>
          <label className="flex items-center gap-2 text-cyan-glow/70">
            <input type="checkbox" checked={includeEvents}
                   onChange={(e) => setIncludeEvents(e.target.checked)} />
            Events
          </label>
          <label className="flex items-center gap-2 text-cyan-glow/70">
            <input type="checkbox" checked={includeIncidents}
                   onChange={(e) => setIncludeIncidents(e.target.checked)} />
            Incidents
          </label>
        </div>
        <button onClick={search} disabled={loading}
                className="w-full rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[10px] uppercase font-bold tracking-widest text-emerald-300 disabled:opacity-50">
          {loading ? "Searching..." : "Search"}
        </button>
      </div>

      {result && (
        <div className="glass-panel border border-cyan-glow/20 p-4 space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">
              Results ({result.results_count} of {result.corpus.corpus_size} corpus)
            </h2>
          </div>
          {!result.results.length ? (
            <p className="text-xs text-cyan-glow/40">No matches above threshold.</p>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-auto pr-1">
              {result.results.map((r, i) => (
                <div key={`${r.kind}-${r.id}-${i}`}
                     className="rounded border border-cyan-glow/15 bg-black/40 p-3">
                  <div className="flex items-center justify-between gap-2 text-[10px]">
                    <span className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-2 py-0.5 uppercase tracking-widest text-cyan-glow">
                      {r.kind}
                    </span>
                    <span className="font-mono text-cyan-glow/70">{r.id}</span>
                    <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-emerald-300">
                      {(r.score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <p className="mt-2 text-xs text-cyan-glow font-mono">{r.text_preview}</p>
                  {Object.keys(r.metadata).length > 0 && (
                    <details className="mt-2">
                      <summary className="cursor-pointer text-[10px] text-cyan-glow/50">metadata</summary>
                      <pre className="mt-1 text-[10px] text-cyan-glow/70 font-mono whitespace-pre-wrap">
                        {JSON.stringify(r.metadata, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
