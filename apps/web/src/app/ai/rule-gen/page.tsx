"use client";

import { useState } from "react";

import { aiRulesGenerate } from "@/lib/apiClient";
import type { RuleGenerateResponse } from "@/lib/types";
import {
  HudHeading,
  HudCard,
  HudButton,
  HudField,
  HudInput,
  HudSelect,
  HudTextarea,
  HudPre,
} from "@/components/hud";

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

  const seedFields: [string, string, (v: string) => void][] = [
    ["Title", title, setTitle],
    ["Severity", severity, setSeverity],
    ["Event Type", eventType, setEventType],
    ["Src IP", srcIp, setSrcIp],
    ["Username", username, setUsername],
    ["MITRE (CSV)", mitre, setMitre],
  ];

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
    } catch (e) {
      setError(e instanceof Error ? e.message : "generate error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 p-6">
      <HudHeading level={1} subtitle="TEMPLATE-BASED // OPTIONAL LLM ENRICHMENT // EXPORT-READY">
        Auto Rule Generator — Sigma + Yara from Events
      </HudHeading>

      {error && (
        <HudCard tone="alert" className="p-3 text-xs text-neon-pink">{error}</HudCard>
      )}

      <div className="grid grid-cols-12 gap-4">
        <HudCard className="col-span-5 p-4 space-y-3">
          <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">Event Seed</h2>
          {seedFields.map(([label, val, set]) => (
            <HudField key={label} label={label}>
              <HudInput value={val} onChange={(e) => set(e.target.value)} mono />
            </HudField>
          ))}
          <HudField label="Message / Raw">
            <HudTextarea value={message} onChange={(e) => setMessage(e.target.value)} className="h-32" />
          </HudField>

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
            <HudField label="Prefer LLM">
              <HudSelect value={prefer} onChange={(e) => setPrefer(e.target.value)}>
                <option value="">auto</option>
                <option value="anthropic">anthropic</option>
                <option value="openai">openai</option>
                <option value="stub">stub</option>
              </HudSelect>
            </HudField>
          )}

          <HudButton block variant="matrix" size="sm" loading={loading} onClick={generate}>
            {loading ? "Generating..." : "Generate Rules"}
          </HudButton>
        </HudCard>

        <HudCard className="col-span-7 p-4 space-y-3">
          <h2 className="text-[11px] uppercase tracking-widest text-cyan-glow/70">Generated Rules</h2>
          {!result ? (
            <p className="text-xs text-cyan-glow/40">No rules generated yet.</p>
          ) : (
            <div className="space-y-4">
              {result.llm_enrichment && (
                <HudCard tone="default" className="border-neon-purple/30 p-2 text-[10px] text-purple-300">
                  Enriched via {result.llm_enrichment.provider} / {result.llm_enrichment.model}
                  {" "}({result.llm_enrichment.usage.input_tokens}+{result.llm_enrichment.usage.output_tokens} tokens)
                </HudCard>
              )}

              <div className="text-[10px] text-cyan-glow/60">
                Final seed: <span className="text-cyan-glow font-bold">{result.seed.title}</span>
                {" / sev="}{result.seed.severity}{" / mitre="}{(result.seed.mitre_techniques ?? []).join(",") || "—"}
              </div>

              {result.rules.sigma && (
                <HudPre
                  title="Sigma (YAML)"
                  filename="rule.sigma.yml"
                  mime="text/yaml"
                  text={result.rules.sigma.yaml}
                />
              )}

              {result.rules.yara && (
                <HudPre
                  title="Yara"
                  filename="rule.yar"
                  text={result.rules.yara.text}
                />
              )}
            </div>
          )}
        </HudCard>
      </div>
    </div>
  );
}
