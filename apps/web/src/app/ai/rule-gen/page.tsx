"use client";

import { useState } from "react";

import { aiRulesGenerate } from "@/lib/apiClient";
import type { RuleGenerateResponse } from "@/lib/types";

function copy(text: string) {
  navigator.clipboard.writeText(text);
}

function downloadText(filename: string, content: string, mime = "text/plain") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function AiRuleGenPage() {
  const [title, setTitle] = useState("Suspicious PowerShell EncodedCommand execution");
  const [severity, setSeverity] = useState("high");
  const [eventType, setEventType] = useState("process_creation");
  const [srcIp, setSrcIp] = useState("");
  const [username, setUsername] = useState("");
  const [message, setMessage] = useState(
    "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
  );
  const [mitre, setMitre] = useState("T1059.001,T1027");
  const [genSigma, setGenSigma] = useState(true);
  const [genYara, setGenYara] = useState(true);
  const [enrich, setEnrich] = useState(false);
  const [prefer, setPrefer] = useState("");

  const [result, setResult] = useState<RuleGenerateResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = async () => {
    setLoading(true);
    setError(null);
    try {
      const formats: string[] = [];
      if (genSigma) formats.push("sigma");
      if (genYara) formats.push("yara");
      const r = await aiRulesGenerate({
        title,
        severity,
        event_type: eventType,
        src_ip: srcIp || undefined,
        username: username || undefined,
        message,
        mitre_techniques: mitre.split(",").map((s) => s.trim()).filter(Boolean),
        enrich_with_llm: enrich,
        formats,
        prefer: prefer || undefined,
      });
      setResult(r);
    } catch (e: any) {
      setError(e?.message ?? "generate error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow"
            style={{ fontFamily: "Orbitron, sans-serif" }}>
          Auto Rule Generator — Sigma + Yara from Events
        </h1>
        <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
          TEMPLATE-BASED // OPTIONAL LLM ENRICHMENT // EXPORT-READY
        </p>
      </div>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-300">{error}</div>
      )}

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-5 glass-panel border border-cyan-glow/20 p-4 space-y-3">
          <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">Event Seed</h2>
          {[
            ["Title", title, setTitle],
            ["Severity", severity, setSeverity],
            ["Event Type", eventType, setEventType],
            ["Src IP", srcIp, setSrcIp],
            ["Username", username, setUsername],
            ["MITRE (CSV)", mitre, setMitre],
          ].map(([label, val, set]: any) => (
            <label key={label} className="flex flex-col gap-1 text-[10px]">
              <span className="uppercase tracking-widest text-cyan-glow/60">{label}</span>
              <input value={val} onChange={(e) => set(e.target.value)}
                     className="rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-cyan-glow" />
            </label>
          ))}
          <label className="flex flex-col gap-1 text-[10px]">
            <span className="uppercase tracking-widest text-cyan-glow/60">Message / Raw</span>
            <textarea value={message} onChange={(e) => setMessage(e.target.value)}
                      className="h-32 rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 font-mono text-cyan-glow" />
          </label>

          <div className="grid grid-cols-2 gap-2 text-[10px]">
            <label className="flex items-center gap-2 text-cyan-glow/70">
              <input type="checkbox" checked={genSigma} onChange={(e) => setGenSigma(e.target.checked)} />
              Sigma
            </label>
            <label className="flex items-center gap-2 text-cyan-glow/70">
              <input type="checkbox" checked={genYara} onChange={(e) => setGenYara(e.target.checked)} />
              Yara
            </label>
            <label className="flex items-center gap-2 text-cyan-glow/70 col-span-2">
              <input type="checkbox" checked={enrich} onChange={(e) => setEnrich(e.target.checked)} />
              Enrich with LLM (title/description/MITRE)
            </label>
          </div>

          {enrich && (
            <label className="flex flex-col gap-1 text-[10px]">
              <span className="uppercase tracking-widest text-cyan-glow/60">Prefer LLM</span>
              <select value={prefer} onChange={(e) => setPrefer(e.target.value)}
                      className="rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-cyan-glow">
                <option value="">auto</option>
                <option value="anthropic">anthropic</option>
                <option value="openai">openai</option>
                <option value="stub">stub</option>
              </select>
            </label>
          )}

          <button onClick={generate} disabled={loading}
                  className="w-full rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[10px] uppercase font-bold tracking-widest text-emerald-300 disabled:opacity-50">
            {loading ? "Generating..." : "Generate Rules"}
          </button>
        </div>

        <div className="col-span-7 glass-panel border border-cyan-glow/20 p-4 space-y-3">
          <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">Generated Rules</h2>
          {!result ? (
            <p className="text-xs text-cyan-glow/40">No rules generated yet.</p>
          ) : (
            <div className="space-y-4">
              {result.llm_enrichment && (
                <div className="rounded border border-purple-500/30 bg-purple-500/10 p-2 text-[10px] text-purple-300">
                  Enriched via {result.llm_enrichment.provider} / {result.llm_enrichment.model}
                  {" "}({result.llm_enrichment.usage.input_tokens}+{result.llm_enrichment.usage.output_tokens} tokens)
                </div>
              )}

              <div className="text-[10px] text-cyan-glow/60">
                Final seed: <span className="text-cyan-glow font-bold">{result.seed.title}</span>
                {" / sev="}{result.seed.severity}{" / mitre="}{(result.seed.mitre_techniques ?? []).join(",") || "—"}
              </div>

              {result.rules.sigma && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60">Sigma (YAML)</div>
                    <div className="flex gap-2">
                      <button onClick={() => copy(result.rules.sigma!.yaml)}
                              className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-2 py-0.5 text-[10px] uppercase text-cyan-glow">
                        Copy
                      </button>
                      <button onClick={() => downloadText("rule.sigma.yml", result.rules.sigma!.yaml, "text/yaml")}
                              className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-2 py-0.5 text-[10px] uppercase text-cyan-glow">
                        Download
                      </button>
                    </div>
                  </div>
                  <pre className="max-h-[280px] overflow-auto rounded border border-cyan-glow/10 bg-black/60 p-3 font-mono text-[10px] text-cyan-glow whitespace-pre-wrap">
                    {result.rules.sigma.yaml}
                  </pre>
                </div>
              )}

              {result.rules.yara && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60">Yara</div>
                    <div className="flex gap-2">
                      <button onClick={() => copy(result.rules.yara!.text)}
                              className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-2 py-0.5 text-[10px] uppercase text-cyan-glow">
                        Copy
                      </button>
                      <button onClick={() => downloadText("rule.yar", result.rules.yara!.text)}
                              className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-2 py-0.5 text-[10px] uppercase text-cyan-glow">
                        Download
                      </button>
                    </div>
                  </div>
                  <pre className="max-h-[280px] overflow-auto rounded border border-cyan-glow/10 bg-black/60 p-3 font-mono text-[10px] text-cyan-glow whitespace-pre-wrap">
                    {result.rules.yara.text}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
