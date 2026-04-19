"use client";

import { useEffect, useState } from "react";

import {
  aiStatus,
  aiTriageEvent,
  aiTriageIncident,
  aiTriageInline,
} from "@/lib/apiClient";
import type { AiStatus, TriageResult } from "@/lib/types";
import {
  HudHeading,
  HudCard,
  HudBadge,
  HudButton,
  HudTabs,
  HudField,
  HudInput,
  HudTextarea,
  HudSelect,
  type HudTabItem,
} from "@/components/hud";

const VERDICT_TONE: Record<string, "tp" | "fp" | "review"> = {
  true_positive: "tp",
  false_positive: "fp",
  needs_review: "review",
};

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-gray-400",
};

type Tab = "Inline" | "By Event ID" | "By Incident ID";

const TABS: ReadonlyArray<HudTabItem<Tab>> = [
  { id: "Inline", label: "Inline" },
  { id: "By Event ID", label: "By Event ID" },
  { id: "By Incident ID", label: "By Incident ID" },
];

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
      <div className="flex items-start justify-between gap-4">
        <HudHeading
          level={1}
          caret
          subtitle="VERDICT // CONFIDENCE // MITRE ATT&CK // RECOMMENDED ACTIONS"
        >
          AI Triage Agent — LLM-Powered SOC Analyst
        </HudHeading>
        {status && (
          <HudCard className="p-3 text-[10px] text-cyan-glow/80 space-y-1 min-w-[220px]">
            <div>
              Provider:{" "}
              <span className="text-cyan-glow font-bold">{status.default_provider}</span>
            </div>
            <div className="flex items-center gap-2">
              <HudBadge tone={status.anthropic_available ? "matrix" : "neutral"}>
                {status.anthropic_available ? "✓" : "✗"} Anthropic
              </HudBadge>
              <span className="text-cyan-glow/50 font-mono">{status.anthropic_model}</span>
            </div>
            <div className="flex items-center gap-2">
              <HudBadge tone={status.openai_available ? "matrix" : "neutral"}>
                {status.openai_available ? "✓" : "✗"} OpenAI
              </HudBadge>
              <span className="text-cyan-glow/50 font-mono">{status.openai_model}</span>
            </div>
          </HudCard>
        )}
      </div>

      <HudTabs items={TABS} value={tab} onChange={setTab} />

      {error && (
        <HudCard tone="alert" scanlines className="p-3 text-xs text-neon-pink">
          {error}
        </HudCard>
      )}

      <div className="grid grid-cols-12 gap-4">
        <HudCard corners className="col-span-5 p-4 space-y-3">
          {tab === "Inline" && (
            <>
              <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">
                Event Details
              </h2>
              {[
                ["Title", title, setTitle],
                ["Severity", severity, setSeverity],
                ["Src IP", srcIp, setSrcIp],
                ["Username", username, setUsername],
                ["Event Type", eventType, setEventType],
              ].map(([label, val, set]: any) => (
                <HudField key={label} label={label}>
                  <HudInput value={val} onChange={(e) => set(e.target.value)} />
                </HudField>
              ))}
              <HudField label="Message">
                <HudTextarea
                  className="h-32"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                />
              </HudField>
            </>
          )}
          {tab === "By Event ID" && (
            <HudField label="Event ID">
              <HudInput
                mono
                value={eventId}
                onChange={(e) => setEventId(e.target.value)}
                placeholder="e.g. evt_abc123"
              />
            </HudField>
          )}
          {tab === "By Incident ID" && (
            <HudField label="Incident ID">
              <HudInput
                mono
                value={incidentId}
                onChange={(e) => setIncidentId(e.target.value)}
                placeholder="e.g. inc_abc123"
              />
            </HudField>
          )}
          <HudField label="Prefer (optional)">
            <HudSelect value={prefer} onChange={(e) => setPrefer(e.target.value)}>
              <option value="">auto</option>
              <option value="anthropic">anthropic</option>
              <option value="openai">openai</option>
              <option value="stub">stub</option>
            </HudSelect>
          </HudField>
          <HudButton block variant="matrix" loading={loading} onClick={run}>
            {loading ? "Analyzing…" : "Run Triage"}
          </HudButton>
        </HudCard>

        <HudCard corners="lg" className="col-span-7 p-4 space-y-3">
          <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">
            Triage Result
          </h2>
          {!result ? (
            <p className="text-xs text-cyan-glow/40">No triage run yet.</p>
          ) : (
            <>
              <div className="grid grid-cols-3 gap-2">
                <HudCard
                  tone={
                    result.triage.verdict === "true_positive"
                      ? "alert"
                      : result.triage.verdict === "false_positive"
                      ? "matrix"
                      : "default"
                  }
                  className="p-2 text-[10px] uppercase tracking-widest font-bold"
                >
                  <div className="opacity-60">Verdict</div>
                  <div
                    className={
                      result.triage.verdict === "true_positive"
                        ? "text-neon-pink"
                        : result.triage.verdict === "false_positive"
                        ? "text-matrix-green"
                        : "text-yellow-300"
                    }
                  >
                    {result.triage.verdict}
                  </div>
                </HudCard>
                <HudCard className="p-2 text-[10px]">
                  <div className="hud-label">Severity</div>
                  <div className={`text-lg font-bold ${SEV_COLOR[result.triage.severity] ?? "text-cyan-glow"}`}>
                    {result.triage.severity}
                  </div>
                </HudCard>
                <HudCard className="p-2 text-[10px]">
                  <div className="hud-label">Confidence</div>
                  <div className="text-lg font-bold text-cyan-glow tabular-nums">
                    {((result.triage.confidence ?? 0) * 100).toFixed(0)}%
                  </div>
                </HudCard>
              </div>

              <div>
                <div className="hud-label mb-1">Summary</div>
                <p className="text-xs text-cyan-glow">{result.triage.summary}</p>
              </div>

              <div>
                <div className="hud-label mb-1">Root Cause</div>
                <p className="text-xs text-cyan-glow/80">{result.triage.root_cause_hypothesis}</p>
              </div>

              <div>
                <div className="hud-label mb-1">Recommended Actions</div>
                <ul className="list-disc pl-5 text-xs text-cyan-glow space-y-1">
                  {(result.triage.recommended_actions ?? []).map((a, i) => (
                    <li key={i}>{a}</li>
                  ))}
                </ul>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="hud-label mb-1">MITRE ATT&CK</div>
                  <div className="flex flex-wrap gap-1">
                    {(result.triage.mitre_techniques ?? []).map((t, i) => (
                      <HudBadge key={i} tone="purple" mono>
                        {t}
                      </HudBadge>
                    ))}
                    {!(result.triage.mitre_techniques?.length ?? 0) && (
                      <span className="text-[10px] text-cyan-glow/40">none</span>
                    )}
                  </div>
                </div>
                <div>
                  <div className="hud-label mb-1">IOCs</div>
                  <div className="flex flex-wrap gap-1">
                    {(result.triage.iocs ?? []).map((t, i) => (
                      <HudBadge key={i} tone="warn" mono>
                        {t}
                      </HudBadge>
                    ))}
                    {!(result.triage.iocs?.length ?? 0) && (
                      <span className="text-[10px] text-cyan-glow/40">none</span>
                    )}
                  </div>
                </div>
              </div>

              <div className="text-[10px] text-cyan-glow/40 font-mono">
                Provider: {result.llm?.provider ?? "-"} • Model: {result.llm?.model ?? "-"} • Tokens:{" "}
                {result.llm?.usage?.input_tokens ?? 0}/{result.llm?.usage?.output_tokens ?? 0}
              </div>
            </>
          )}
        </HudCard>
      </div>
    </div>
  );
}
