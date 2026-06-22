"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  complianceFrameworks,
  complianceGlobalReport,
  runFrameworkReport,
  listPentestReportTemplates,
  listPentestReportHistory,
  generateReport,
  type PentestReportTemplateApi,
  type PentestReportHistoryEntryApi,
  type PentestReportRequestBody,
} from "@/lib/apiClient";
import type { ComplianceFrameworkInfo, ComplianceGlobalReport } from "@/lib/types";
import {
  HudHeading,
  HudCard,
  HudButton,
  HudStat,
  HudTabs,
  HudField,
  HudInput,
  HudSelect,
  type HudTabItem,
} from "@/components/hud";

type Tab = "templates" | "compliance" | "history" | "generate";

function Badge({ text, cls }: { text: string; cls: string }) {
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>
      {text}
    </span>
  );
}

function formatBytes(n?: number) {
  if (!n) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export default function ReportsPage() {
  const [activeTab, setActiveTab] = useState<Tab>("templates");

  const [frameworks, setFrameworks] = useState<ComplianceFrameworkInfo[]>([]);
  const [globalReport, setGlobalReport] = useState<ComplianceGlobalReport | null>(null);
  const [templates, setTemplates] = useState<PentestReportTemplateApi[]>([]);
  const [history, setHistory] = useState<PentestReportHistoryEntryApi[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedTemplate, setSelectedTemplate] = useState<string>("");
  const [generating, setGenerating] = useState(false);
  const [generatedInfo, setGeneratedInfo] = useState<string | null>(null);

  const [form, setForm] = useState<PentestReportRequestBody>({
    title: "Rapport de Pentest",
    client: "Client Corp",
    tester: "Red Team Operator",
    scope: [],
    scan_ids: [],
    classification: "CONFIDENTIAL",
    include_evidence: true,
    include_remediation: true,
    language: "fr",
    template: "standard",
  });

  const [frameworkBusy, setFrameworkBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [tpls, fws, global, hist] = await Promise.all([
        listPentestReportTemplates(),
        complianceFrameworks(),
        complianceGlobalReport(),
        listPentestReportHistory(),
      ]);
      setTemplates(tpls.templates ?? []);
      setFrameworks(fws.frameworks ?? []);
      setGlobalReport(global);
      setHistory(hist.reports ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur chargement reports");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function runFramework(fid: string) {
    setFrameworkBusy(fid);
    try {
      await runFrameworkReport(fid);
      const refreshed = await complianceGlobalReport();
      setGlobalReport(refreshed);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur run framework");
    } finally {
      setFrameworkBusy(null);
    }
  }

  async function onGenerate() {
    if (!form.title.trim() || !form.client.trim()) {
      setError("Title et client requis");
      return;
    }
    setGenerating(true);
    setGeneratedInfo(null);
    setError(null);
    try {
      const body: PentestReportRequestBody = { ...form, template: selectedTemplate || form.template };
      const url = await generateReport(body as unknown as Record<string, unknown>);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${form.title.replace(/\s+/g, "_")}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      setGeneratedInfo("Rapport généré — téléchargement lancé");
      const hist = await listPentestReportHistory();
      setHistory(hist.reports ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur génération");
    } finally {
      setGenerating(false);
    }
  }

  const totalCoverage = useMemo(() => {
    if (!globalReport?.summary?.length) return 0;
    const sum = globalReport.summary.reduce((acc: number, s) => acc + (s.coverage_score ?? 0), 0);
    return sum / globalReport.summary.length;
  }, [globalReport]);

  const tabs: HudTabItem<Tab>[] = [
    { id: "templates", label: "Templates" },
    { id: "compliance", label: "Compliance" },
    { id: "history", label: "History" },
    { id: "generate", label: "Generate" },
  ];

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <HudHeading level={1} subtitle="COMPLIANCE FRAMEWORKS // PENTEST REPORTS">
          Report Center
        </HudHeading>
        <div className="flex items-center gap-2">
          <HudTabs items={tabs} value={activeTab} onChange={setActiveTab} />
          <HudButton variant="secondary" size="sm" onClick={load}>
            {loading ? "..." : "REFRESH"}
          </HudButton>
        </div>
      </div>

      <div className="cyan-line" />

      {error && (
        <HudCard tone="alert" className="p-3 text-xs text-neon-pink">{error}</HudCard>
      )}

      {/* Templates */}
      {activeTab === "templates" && (
        <>
          <div className="grid grid-cols-3 gap-4">
            {templates.map((t) => (
              <HudCard
                key={t.id}
                className={`cursor-pointer p-5 transition-all ${
                  selectedTemplate === t.id
                    ? "border-cyan-glow/30 shadow-cyan-sm"
                    : "hover:border-cyan-glow/20"
                }`}
                onClick={() => {
                  setSelectedTemplate(t.id);
                  setForm((f) => ({ ...f, template: t.id }));
                }}
              >
                <div className="mb-3 flex items-center justify-between">
                  <h3 className="text-sm font-bold text-gray-200">{t.name}</h3>
                  {t.estimated_pages && (
                    <Badge text={`${t.estimated_pages}p`} cls="bg-cyan-glow/10 text-cyan-glow/70 border-cyan-glow/20" />
                  )}
                </div>
                <p className="text-[10px] text-gray-500">{t.description}</p>
                <div className="mt-3 flex flex-wrap gap-1">
                  {t.sections.map((s) => (
                    <span key={s} className="rounded bg-cyan-glow/5 px-2 py-0.5 text-[8px] text-cyan-glow/50">{s}</span>
                  ))}
                </div>
              </HudCard>
            ))}
          </div>
          {selectedTemplate && (
            <HudCard className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-gray-500">Template sélectionné</div>
                  <div className="mt-1 text-sm font-bold text-cyan-glow">
                    {templates.find((t) => t.id === selectedTemplate)?.name}
                  </div>
                </div>
                <HudButton variant="primary" size="sm" onClick={() => setActiveTab("generate")}>
                  UTILISER CE TEMPLATE
                </HudButton>
              </div>
            </HudCard>
          )}
        </>
      )}

      {/* Compliance */}
      {activeTab === "compliance" && (
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <HudStat label="FRAMEWORKS" value={frameworks.length} />
            <HudStat label="COUVERTURE MOYENNE" value={`${totalCoverage.toFixed(1)}%`} tone="matrix" />
            <HudStat
              label="CONTRÔLES TOTAL"
              value={(globalReport?.summary ?? []).reduce((a: number, s) => a + s.controls_total, 0)}
            />
          </div>

          <HudCard className="overflow-hidden p-0">
            <table className="w-full">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Framework</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Version</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Controls</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Coverage</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Breakdown</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Actions</th>
                </tr>
              </thead>
              <tbody>
                {frameworks.map((fw) => {
                  const sum = globalReport?.summary?.find((s) => s.id === fw.id);
                  const cov = sum?.coverage_score ?? 0;
                  const covColor = cov >= 80 ? "text-emerald-400" : cov >= 50 ? "text-yellow-400" : "text-red-400";
                  return (
                    <tr key={fw.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                      <td className="px-4 py-2">
                        <div className="text-[11px] font-bold text-gray-200">{fw.name}</div>
                        <div className="text-[9px] text-gray-500 truncate max-w-[320px]">{fw.description}</div>
                      </td>
                      <td className="px-4 py-2 text-[10px] text-gray-400">{fw.version ?? "-"}</td>
                      <td className="px-4 py-2 text-[10px] text-gray-300">{sum?.controls_total ?? fw.controls_count ?? 0}</td>
                      <td className="px-4 py-2">
                        <div className="flex items-center gap-2">
                          <span className={`text-[11px] font-bold ${covColor}`}>{cov.toFixed(1)}%</span>
                          <div className="w-24 h-2 bg-black/40 rounded">
                            <div className={`h-full rounded ${cov >= 80 ? "bg-emerald-500" : cov >= 50 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${cov}%` }} />
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-2">
                        {sum ? (
                          <div className="flex gap-1 text-[9px]">
                            <span className="text-emerald-400">{sum.by_status.covered}✓</span>
                            <span className="text-yellow-400">{sum.by_status.partial}~</span>
                            <span className="text-red-400">{sum.by_status.uncovered}✗</span>
                            <span className="text-gray-500">{sum.by_status.manual}⊡</span>
                          </div>
                        ) : <span className="text-[9px] text-gray-600">—</span>}
                      </td>
                      <td className="px-4 py-2">
                        <HudButton
                          size="sm"
                          variant="secondary"
                          disabled={frameworkBusy === fw.id}
                          onClick={() => runFramework(fw.id)}
                        >
                          {frameworkBusy === fw.id ? "..." : "RUN"}
                        </HudButton>
                      </td>
                    </tr>
                  );
                })}
                {frameworks.length === 0 && !loading && (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-xs text-gray-500">Aucun framework disponible.</td></tr>
                )}
              </tbody>
            </table>
          </HudCard>
        </div>
      )}

      {/* History */}
      {activeTab === "history" && (
        <HudCard className="overflow-hidden p-0">
          <table className="w-full">
            <thead>
              <tr className="border-b border-cyan-glow/10">
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Report</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Client</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Template</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Generated</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Format</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Size</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Status</th>
              </tr>
            </thead>
            <tbody>
              {history.map((rh) => (
                <tr key={rh.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                  <td className="px-4 py-2 text-[11px] font-bold text-gray-200">{rh.title ?? rh.id}</td>
                  <td className="px-4 py-2 text-[10px] text-gray-400">{rh.client ?? "-"}</td>
                  <td className="px-4 py-2 text-[10px] text-gray-400">{rh.template ?? "-"}</td>
                  <td className="px-4 py-2 font-mono text-[10px] text-gray-500">{rh.created_at ? new Date(rh.created_at).toLocaleString() : "-"}</td>
                  <td className="px-4 py-2">
                    <Badge text={(rh.format ?? "pdf").toUpperCase()} cls="bg-cyan-glow/10 text-cyan-glow/70 border-cyan-glow/20" />
                  </td>
                  <td className="px-4 py-2 text-[10px] text-gray-500">{formatBytes(rh.size_bytes)}</td>
                  <td className="px-4 py-2 text-[10px] text-emerald-400">{rh.status ?? "ready"}</td>
                </tr>
              ))}
              {history.length === 0 && !loading && (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-xs text-gray-500">
                  Aucun rapport. Génère-en un via l&apos;onglet <span className="text-cyan-glow">generate</span>.
                </td></tr>
              )}
            </tbody>
          </table>
        </HudCard>
      )}

      {/* Generate */}
      {activeTab === "generate" && (
        <HudCard className="p-5 space-y-4">
          <h3 className="text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Générer un rapport de pentest
          </h3>
          <div className="grid grid-cols-2 gap-4">
            <HudField label="Titre">
              <HudInput
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
              />
            </HudField>
            <HudField label="Client">
              <HudInput
                value={form.client}
                onChange={(e) => setForm({ ...form, client: e.target.value })}
              />
            </HudField>
            <HudField label="Testeur">
              <HudInput
                value={form.tester}
                onChange={(e) => setForm({ ...form, tester: e.target.value })}
              />
            </HudField>
            <HudField label="Classification">
              <HudSelect
                value={form.classification}
                onChange={(e) => setForm({ ...form, classification: e.target.value })}
              >
                <option value="PUBLIC">PUBLIC</option>
                <option value="INTERNAL">INTERNAL</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                <option value="RESTRICTED">RESTRICTED</option>
              </HudSelect>
            </HudField>
            <HudField label="Scope (CSV)">
              <HudInput
                value={(form.scope ?? []).join(",")}
                onChange={(e) => setForm({ ...form, scope: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
                placeholder="example.com, 10.0.0.0/24"
                mono
              />
            </HudField>
            <HudField label="Scan IDs (CSV)">
              <HudInput
                value={(form.scan_ids ?? []).join(",")}
                onChange={(e) => setForm({ ...form, scan_ids: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
                placeholder="scan-123, scan-456"
                mono
              />
            </HudField>
            <HudField label="Langue">
              <HudSelect
                value={form.language}
                onChange={(e) => setForm({ ...form, language: e.target.value })}
              >
                <option value="fr">Français</option>
                <option value="en">English</option>
              </HudSelect>
            </HudField>
            <HudField label="Template">
              <HudSelect
                value={selectedTemplate || form.template}
                onChange={(e) => {
                  setSelectedTemplate(e.target.value);
                  setForm({ ...form, template: e.target.value });
                }}
              >
                {templates.map((t) => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </HudSelect>
            </HudField>
          </div>
          <div className="flex gap-4 text-[10px] text-gray-300">
            <label className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={!!form.include_evidence}
                onChange={(e) => setForm({ ...form, include_evidence: e.target.checked })}
              />
              Inclure preuves
            </label>
            <label className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={!!form.include_remediation}
                onChange={(e) => setForm({ ...form, include_remediation: e.target.checked })}
              />
              Inclure remediation
            </label>
          </div>
          <div className="flex items-center gap-3">
            <HudButton variant="primary" loading={generating} onClick={onGenerate}>
              {generating ? "GENERATING..." : "GÉNÉRER RAPPORT"}
            </HudButton>
            {generatedInfo && (
              <span className="text-[11px] text-emerald-400">{generatedInfo}</span>
            )}
          </div>
        </HudCard>
      )}
    </div>
  );
}
