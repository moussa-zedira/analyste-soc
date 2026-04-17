"use client";

import { useEffect, useState } from "react";

import {
  aiStatus,
  aiTriageEvent,
  aiTriageIncident,
  aiTriageInline,
} from "@/lib/apiClient";
import type { AiStatus, TriageResult } from "@/lib/types";

const VERDICT_COLOR: Record<string, string> = {
  true_positive: "border-red-500/40 bg-red-500/10 text-red-300",
  false_positive: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  needs_review: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
};
const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-gray-400",
};

const TABS = ["Inline", "By Event ID", "By Incident ID"] as const;
type Tab = (typeof TABS)[number];

export default function AiTriagePage() {
  const [tab, setTab] = useState<Tab>("Inline");
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [prefer, setPrefer] = useState<string>("");
  const [result, setResult] = useState<TriageResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Inline
  const [title, setTitle] = useState("Possible SSH brute force from external IP");
  const [severity, setSeverity] = useState("high");
  const [srcIp, setSrcIp] = useState("203.0.113.42");
  const [username, setUsername] = useState("admin");
  const [eventType, setEventType] = useState("auth_failure");
  const [message, setMessage] = useState(
    "Failed password for invalid user admin from 203.0.113.42 port 51234 ssh2 (15 attempts in 60s)"
  );

  // By ID
  const [eventId, setEventId] = useState("");
  const [incidentId, setIncidentId] = useState("");

  useEffect(() => {
    aiStatus().then(setStatus).catch(() => {});
  }, []);

  const run = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      let r: TriageResult;
      if (tab === "Inline") {
        r = await aiTriageInline({
          title, severity, src_ip: srcIp, username, event_type: eventType,
          message, prefer: prefer || undefined,
        });
      } else if (tab === "By Event ID") {
        r = await aiTriageEvent(eventId, prefer || undefined);
      } else {
        r = await aiTriageIncident(incidentId, prefer || undefined);
      }
      setResult(r);
    } catch (e: any) {
      setError(e?.message ?? "triage error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow"
              style={{ fontFamily: "Orbitron, sans-serif" }}>
            AI Triage Agent — LLM-Powered SOC Analyst
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            VERDICT // CONFIDENCE // MITRE ATT&CK // RECOMMENDED ACTIONS
          </p>
        </div>
        {status && (
          <div className="rounded border border-cyan-glow/20 bg-black/40 p-2 text-[10px] text-cyan-glow/70">
            <div>Provider: <span className="text-cyan-glow font-bold">{status.default_provider}</span></div>
            <div className="mt-1">
              {status.anthropic_available ? "✓" : "✗"} Anthropic ({status.anthropic_model})
            </div>
            <div>{status.openai_available ? "✓" : "✗"} OpenAI ({status.openai_model})</div>
          </div>
        )}
      </div>

      <div className="flex gap-2">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded border px-3 py-1 text-[11px] uppercase tracking-widest ${
              tab === t
                ? "border-cyan-glow bg-cyan-glow/20 text-cyan-glow"
                : "border-cyan-glow/20 bg-black/40 text-cyan-glow/70"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-300">{error}</div>
      )}

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-5 glass-panel border border-cyan-glow/20 p-4 space-y-3">
          {tab === "Inline" && (
            <>
              <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">Event Details</h2>
              {[
                ["Title", title, setTitle],
                ["Severity", severity, setSeverity],
                ["Src IP", srcIp, setSrcIp],
                ["Username", username, setUsername],
                ["Event Type", eventType, setEventType],
              ].map(([label, val, set]: any) => (
                <label key={label} className="flex flex-col gap-1 text-[10px]">
                  <span className="uppercase tracking-widest text-cyan-glow/60">{label}</span>
                  <input value={val} onChange={(e) => set(e.target.value)}
                         className="rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-cyan-glow" />
                </label>
              ))}
              <label className="flex flex-col gap-1 text-[10px]">
                <span className="uppercase tracking-widest text-cyan-glow/60">Message</span>
                <textarea value={message} onChange={(e) => setMessage(e.target.value)}
                          className="h-32 rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 font-mono text-cyan-glow" />
              </label>
            </>
          )}
          {tab === "By Event ID" && (
            <>
              <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">Event ID</h2>
              <input value={eventId} onChange={(e) => setEventId(e.target.value)}
                     placeholder="e.g. evt_abc123"
                     className="w-full rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-cyan-glow" />
            </>
          )}
          {tab === "By Incident ID" && (
            <>
              <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">Incident ID</h2>
              <input value={incidentId} onChange={(e) => setIncidentId(e.target.value)}
                     placeholder="e.g. inc_abc123"
                     className="w-full rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-cyan-glow" />
            </>
          )}
          <label className="flex flex-col gap-1 text-[10px]">
            <span className="uppercase tracking-widest text-cyan-glow/60">Prefer (optional)</span>
            <select value={prefer} onChange={(e) => setPrefer(e.target.value)}
                    className="rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-cyan-glow">
              <option value="">auto</option>
              <option value="anthropic">anthropic</option>
              <option value="openai">openai</option>
              <option value="stub">stub</option>
            </select>
          </label>
          <button onClick={run} disabled={loading}
                  className="w-full rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[10px] uppercase font-bold tracking-widest text-emerald-300 disabled:opacity-50">
            {loading ? "Analyzing..." : "Run Triage"}
          </button>
        </div>

        <div className="col-span-7 glass-panel border border-cyan-glow/20 p-4 space-y-3">
          <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">Triage Result</h2>
          {!result ? (
            <p className="text-xs text-cyan-glow/40">No triage run yet.</p>
          ) : (
            <>
              <div className="grid grid-cols-3 gap-2">
                <div className={`rounded border p-2 text-[10px] uppercase tracking-widest font-bold ${VERDICT_COLOR[result.triage.verdict] ?? "border-cyan-glow/30 bg-black/40 text-cyan-glow"}`}>
                  <div className="opacity-60">Verdict</div>
                  <div>{result.triage.verdict}</div>
                </div>
                <div className="rounded border border-cyan-glow/20 bg-black/40 p-2 text-[10px]">
                  <div className="text-cyan-glow/60 uppercase tracking-widest">Severity</div>
                  <div className={`text-lg font-bold ${SEV_COLOR[result.triage.severity] ?? "text-cyan-glow"}`}>
                    {result.triage.severity}
                  </div>
                </div>
                <div className="rounded border border-cyan-glow/20 bg-black/40 p-2 text-[10px]">
                  <div className="text-cyan-glow/60 uppercase tracking-widest">Confidence</div>
                  <div className="text-lg font-bold text-cyan-glow">
                    {(result.triage.confidence * 100).toFixed(0)}%
                  </div>
                </div>
              </div>

              <div>
                <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60 mb-1">Summary</div>
                <p className="text-xs text-cyan-glow">{result.triage.summary}</p>
              </div>

              <div>
                <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60 mb-1">Root Cause</div>
                <p className="text-xs text-cyan-glow/80">{result.triage.root_cause_hypothesis}</p>
              </div>

              <div>
                <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60 mb-1">Recommended Actions</div>
                <ul className="list-disc pl-5 text-xs text-cyan-glow space-y-1">
                  {result.triage.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
                </ul>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60 mb-1">MITRE ATT&CK</div>
                  <div className="flex flex-wrap gap-1">
                    {result.triage.mitre_techniques.map((t, i) => (
                      <span key={i} className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 text-[10px] font-mono text-purple-300">
                        {t}
                      </span>
                    ))}
                    {!result.triage.mitre_techniques.length && (
                      <span className="text-[10px] text-cyan-glow/40">none</span>
                    )}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60 mb-1">IOCs</div>
                  <div className="flex flex-wrap gap-1">
                    {result.triage.iocs.map((t, i) => (
                      <span key={i} className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-mono text-amber-300">
                        {t}
                      </span>
                    ))}
                    {!result.triage.iocs.length && (
                      <span className="text-[10px] text-cyan-glow/40">none</span>
                    )}
                  </div>
                </div>
              </div>

              <div className="text-[10px] text-cyan-glow/40">
                Provider: {result.llm.provider} • Model: {result.llm.model} • Tokens: {result.llm.usage.input_tokens}/{result.llm.usage.output_tokens}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
