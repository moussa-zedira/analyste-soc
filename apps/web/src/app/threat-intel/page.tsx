"use client";

import { useCallback, useEffect, useState } from "react";
import {
  lookupIP,
  getTIStats,
  listSigmaRules,
  importSigmaRule,
  toggleSigmaRule,
  deleteSigmaRule,
} from "@/lib/apiClient";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import type { TILookupResult, TIStatsResponse, SigmaRuleInfo } from "@/lib/types";

export default function ThreatIntelPage() {
  const [activeTab, setActiveTab] = useState<"lookup" | "sigma" | "stats">("lookup");

  // Lookup state
  const [lookupIp, setLookupIp] = useState("");
  const [lookupResult, setLookupResult] = useState<TILookupResult | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);

  // Stats state
  const [stats, setStats] = useState<TIStatsResponse | null>(null);

  // SIGMA state
  const [sigmaRules, setSigmaRules] = useState<SigmaRuleInfo[]>([]);
  const [sigmaYaml, setSigmaYaml] = useState("");
  const [sigmaImporting, setSigmaImporting] = useState(false);
  const [sigmaError, setSigmaError] = useState<string | null>(null);

  const loadStats = useCallback(async () => {
    try {
      const data = await getTIStats();
      setStats(data);
    } catch {
      /* ignore */
    }
  }, []);

  const loadSigma = useCallback(async () => {
    try {
      const data = await listSigmaRules();
      setSigmaRules(data);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    loadStats();
    loadSigma();
  }, [loadStats, loadSigma]);

  const handleLookup = async () => {
    if (!lookupIp.trim()) return;
    setLookupLoading(true);
    setLookupError(null);
    setLookupResult(null);
    try {
      const result = await lookupIP(lookupIp.trim());
      setLookupResult(result);
    } catch (err: unknown) {
      setLookupError(err instanceof Error ? err.message : "Erreur de lookup");
    } finally {
      setLookupLoading(false);
    }
  };

  const handleImportSigma = async () => {
    if (!sigmaYaml.trim()) return;
    setSigmaImporting(true);
    setSigmaError(null);
    try {
      await importSigmaRule(sigmaYaml);
      setSigmaYaml("");
      await loadSigma();
    } catch (err: unknown) {
      setSigmaError(err instanceof Error ? err.message : "Erreur d'import");
    } finally {
      setSigmaImporting(false);
    }
  };

  const handleToggle = async (id: number, enabled: boolean) => {
    await toggleSigmaRule(id, enabled);
    await loadSigma();
  };

  const handleDelete = async (id: number) => {
    await deleteSigmaRule(id);
    await loadSigma();
  };

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Threat Intelligence
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            LOOKUP IP // SIGMA RULES // ENRICHISSEMENT
          </p>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Tabs */}
      <StaggerItem>
        <div className="flex gap-2">
          {(["lookup", "sigma", "stats"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`rounded-md border px-4 py-2 text-[10px] font-bold tracking-widest transition-all ${
                activeTab === tab
                  ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow"
                  : "border-gray-700 text-gray-500 hover:border-gray-600"
              }`}
            >
              {tab === "lookup" ? "IP LOOKUP" : tab === "sigma" ? "SIGMA RULES" : "STATISTIQUES"}
            </button>
          ))}
        </div>
      </StaggerItem>

      {/* IP Lookup Tab */}
      {activeTab === "lookup" && (
        <StaggerItem>
          <div className="glass-panel p-6 space-y-4">
            <div className="flex gap-3">
              <input
                type="text"
                value={lookupIp}
                onChange={(e) => setLookupIp(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleLookup()}
                placeholder="Entrer une adresse IP (ex: 185.220.101.1)"
                className="flex-1 rounded-md border border-gray-700 bg-gray-900/80 px-4 py-2.5 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none"
              />
              <button
                onClick={handleLookup}
                disabled={lookupLoading}
                className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50"
              >
                {lookupLoading ? "ANALYSE..." : "LOOKUP"}
              </button>
            </div>

            {lookupError && (
              <div className="rounded border border-red-500/30 bg-red-500/5 px-4 py-2 text-xs text-red-400">
                {lookupError}
              </div>
            )}

            {lookupResult && (
              <div className="space-y-4">
                {/* Score header */}
                <div className="flex items-center gap-4">
                  <div
                    className={`rounded-full px-4 py-2 text-lg font-bold font-mono ${
                      lookupResult.risk_score >= 70
                        ? "bg-red-500/15 text-red-400 border border-red-500/30"
                        : lookupResult.risk_score >= 30
                          ? "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30"
                          : "bg-green-500/15 text-green-400 border border-green-500/30"
                    }`}
                  >
                    {lookupResult.risk_score}/100
                  </div>
                  <div>
                    <p className="text-sm font-mono text-gray-200">{lookupResult.ip}</p>
                    <p className={`text-xs font-bold ${lookupResult.is_malicious ? "text-red-400" : "text-green-400"}`}>
                      {lookupResult.is_malicious ? "MALICIOUS" : "CLEAN"}
                    </p>
                  </div>
                </div>

                {/* Tags */}
                {lookupResult.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {lookupResult.tags.map((tag) => (
                      <span
                        key={tag}
                        className="rounded-full border border-cyan-glow/20 bg-cyan-glow/5 px-2.5 py-0.5 text-[10px] text-cyan-glow"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}

                {/* Providers */}
                {lookupResult.providers.map((p, i) => (
                  <div
                    key={i}
                    className="rounded-lg border border-gray-800 p-3 space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-gray-300 uppercase">{p.source}</span>
                      <span className="text-xs font-mono text-gray-400">
                        Score: {p.risk_score} / Reports: {p.total_reports}
                        {p.cached && <span className="ml-2 text-gray-600">(cache)</span>}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </StaggerItem>
      )}

      {/* SIGMA Rules Tab */}
      {activeTab === "sigma" && (
        <StaggerItem>
          <div className="space-y-4">
            {/* Import form */}
            <div className="glass-panel p-4 space-y-3">
              <h3 className="text-[10px] font-bold tracking-widest text-gray-500">IMPORTER UNE REGLE SIGMA</h3>
              <textarea
                value={sigmaYaml}
                onChange={(e) => setSigmaYaml(e.target.value)}
                placeholder={"title: Detect Brute Force\nlogsource:\n  category: authentication\ndetection:\n  selection:\n    EventType: auth.fail\n  condition: selection\nlevel: medium"}
                className="w-full rounded-md border border-gray-700 bg-gray-900/80 p-3 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none"
                rows={8}
              />
              {sigmaError && (
                <div className="text-xs text-red-400">{sigmaError}</div>
              )}
              <button
                onClick={handleImportSigma}
                disabled={sigmaImporting || !sigmaYaml.trim()}
                className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50"
              >
                {sigmaImporting ? "IMPORT..." : "IMPORTER"}
              </button>
            </div>

            {/* Rules list */}
            <div className="glass-panel overflow-hidden">
              {sigmaRules.length === 0 ? (
                <div className="p-8 text-center">
                  <p className="text-sm text-gray-400">Aucune regle SIGMA importee</p>
                  <p className="text-[10px] text-gray-600 mt-1">
                    Importez des regles SIGMA YAML pour enrichir la detection
                  </p>
                </div>
              ) : (
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-cyan-glow/10">
                      <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">NOM</th>
                      <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">NIVEAU</th>
                      <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">STATUT</th>
                      <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500 text-right">ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sigmaRules.map((rule) => (
                      <tr key={rule.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                        <td className="px-4 py-3">
                          <p className="text-sm text-gray-200">{rule.name}</p>
                          {rule.description && (
                            <p className="text-[10px] text-gray-500 mt-0.5">{rule.description}</p>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                              rule.level === "high"
                                ? "bg-red-500/15 text-red-400"
                                : rule.level === "medium"
                                  ? "bg-yellow-500/15 text-yellow-400"
                                  : "bg-green-500/15 text-green-400"
                            }`}
                          >
                            {rule.level.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => handleToggle(rule.id, !rule.enabled)}
                            className={`rounded px-2 py-0.5 text-[10px] font-bold transition-colors ${
                              rule.enabled
                                ? "bg-green-500/15 text-green-400 hover:bg-green-500/25"
                                : "bg-gray-700/50 text-gray-500 hover:bg-gray-700"
                            }`}
                          >
                            {rule.enabled ? "ACTIF" : "INACTIF"}
                          </button>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => handleDelete(rule.id)}
                            className="text-[10px] text-red-400/50 hover:text-red-400 transition-colors"
                          >
                            SUPPRIMER
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </StaggerItem>
      )}

      {/* Stats Tab */}
      {activeTab === "stats" && (
        <StaggerItem>
          <div className="space-y-4">
            {stats ? (
              <>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="glass-panel p-4 text-center">
                    <p className="text-2xl font-bold text-cyan-glow font-mono">{stats.cache_entries}</p>
                    <p className="text-[10px] tracking-widest text-gray-500 mt-1">CACHE TI</p>
                  </div>
                  <div className="glass-panel p-4 text-center">
                    <p className="text-2xl font-bold text-cyan-glow font-mono">{stats.providers_configured.length}</p>
                    <p className="text-[10px] tracking-widest text-gray-500 mt-1">PROVIDERS</p>
                  </div>
                  <div className="glass-panel p-4 text-center">
                    <p className="text-2xl font-bold text-cyan-glow font-mono">
                      {stats.abuseipdb_daily_used}/{stats.abuseipdb_daily_limit}
                    </p>
                    <p className="text-[10px] tracking-widest text-gray-500 mt-1">ABUSEIPDB</p>
                  </div>
                  <div className="glass-panel p-4 text-center">
                    <p className="text-2xl font-bold text-cyan-glow font-mono">
                      {stats.otx_hourly_used}/{stats.otx_hourly_limit}
                    </p>
                    <p className="text-[10px] tracking-widest text-gray-500 mt-1">OTX</p>
                  </div>
                </div>

                <div className="glass-panel p-4 space-y-3">
                  <h3 className="text-[10px] font-bold tracking-widest text-gray-500">PROVIDERS CONFIGURES</h3>
                  {stats.providers_configured.length === 0 ? (
                    <div className="space-y-2">
                      <p className="text-xs text-gray-400">Aucun provider configure</p>
                      <p className="text-[10px] text-gray-600">
                        Ajoutez vos cles API dans les variables d&apos;environnement :
                      </p>
                      <div className="rounded border border-gray-700 bg-gray-900/50 p-3 font-mono text-[10px] text-gray-400 space-y-1">
                        <p>ABUSEIPDB_API_KEY=votre-cle-api</p>
                        <p>OTX_API_KEY=votre-cle-api</p>
                      </div>
                    </div>
                  ) : (
                    <div className="flex gap-2">
                      {stats.providers_configured.map((p) => (
                        <span
                          key={p}
                          className="rounded border border-green-500/30 bg-green-500/10 px-3 py-1.5 text-[10px] font-bold text-green-400 uppercase"
                        >
                          {p}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="glass-panel p-8 text-center">
                <p className="hud-label animate-pulse">LOADING STATS...</p>
              </div>
            )}
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
