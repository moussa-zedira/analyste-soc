"use client";

import { useEffect, useState } from "react";

import { aiRagCorpus, aiRagSearch } from "@/lib/apiClient";
import type { RagSearchResult } from "@/lib/types";
import {
  HudHeading,
  HudCard,
  HudButton,
  HudBadge,
  HudStat,
  HudField,
  HudInput,
} from "@/components/hud";

export default function AiRagPage() {
  const [query, setQuery] = useState("");
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
    } catch (e) {
      setError(e instanceof Error ? e.message : "search error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 p-6">
      <HudHeading level={1} subtitle="TF-IDF // COSINE SIMILARITY // EVENTS + INCIDENTS CORPUS">
        RAG — Semantic Search on Historical Logs
      </HudHeading>

      {corpus && (
        <div className="grid grid-cols-3 gap-3">
          <HudStat label="Corpus size" value={corpus.corpus_size} />
          <HudCard className="p-3">
            <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60">By kind</div>
            <div className="mt-1 text-xs text-cyan-glow">
              {Object.entries(corpus.by_kind).map(([k, v]) => (
                <span key={k} className="mr-3">{k}: <span className="font-bold">{v}</span></span>
              ))}
            </div>
          </HudCard>
          <HudStat label="Approx tokens" value={corpus.approx_token_count.toLocaleString()} />
        </div>
      )}

      {error && (
        <HudCard tone="alert" className="p-3 text-xs text-neon-pink">{error}</HudCard>
      )}

      <HudCard className="p-4 space-y-3">
        <HudField label="Query">
          <HudInput
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") search(); }}
            placeholder="What are you looking for?"
            mono
          />
        </HudField>
        <div className="grid grid-cols-4 gap-3 text-[10px]">
          <HudField label="Top K">
            <HudInput type="number" min={1} max={50} value={topK}
              onChange={(e) => setTopK(parseInt(e.target.value || "10"))} />
          </HudField>
          <HudField label="Lookback (h)">
            <HudInput type="number" min={1} max={8760} value={lookback}
              onChange={(e) => setLookback(parseInt(e.target.value || "168"))} />
          </HudField>
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
        <HudButton block variant="matrix" size="sm" loading={loading} disabled={!query.trim()} onClick={search}>
          {loading ? "Searching..." : "Search"}
        </HudButton>
      </HudCard>

      {result && (
        <HudCard className="p-4 space-y-2">
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
                <HudCard key={`${r.kind}-${r.id}-${i}`} variant="deep" className="p-3">
                  <div className="flex items-center justify-between gap-2 text-[10px]">
                    <HudBadge tone="cyan">{r.kind}</HudBadge>
                    <span className="font-mono text-cyan-glow/70">{r.id}</span>
                    <HudBadge tone="matrix" mono>{(r.score * 100).toFixed(1)}%</HudBadge>
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
                </HudCard>
              ))}
            </div>
          )}
        </HudCard>
      )}
    </div>
  );
}
