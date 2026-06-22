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
import {
  HudHeading,
  HudCard,
  HudButton,
  HudBadge,
  HudStat,
  HudTabs,
  HudInput,
  HudTextarea,
  type HudTabItem,
} from "@/components/hud";
import type { TILookupResult, TIStatsResponse, SigmaRuleInfo } from "@/lib/types";

type Tab = "lookup" | "sigma" | "stats";

export default function ThreatIntelPage() {
  const [activeTab, setActiveTab] = useState<Tab>("lookup");

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

  const tabs: HudTabItem<Tab>[] = [
    { id: "lookup", label: "IP Lookup" },
    { id: "sigma", label: "Sigma Rules" },
    { id: "stats", label: "Statistiques" },
  ];

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <HudHeading level={1} subtitle="LOOKUP IP // SIGMA RULES // ENRICHISSEMENT">
          Threat Intelligence
        </HudHeading>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Tabs */}
      <StaggerItem>
        <HudTabs items={tabs} value={activeTab} onChange={setActiveTab} />
      </StaggerItem>

      {/* IP Lookup Tab */}
      {activeTab === "lookup" && (
        <StaggerItem>
          <HudCard className="p-6 space-y-4">
            <div className="flex gap-3">
              <HudInput
                type="text"
                value={lookupIp}
                onChange={(e) => setLookupIp(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleLookup()}
                placeholder="Entrer une adresse IP (ex: 185.220.101.1)"
                className="flex-1"
                mono
              />
              <HudButton variant="primary" loading={lookupLoading} onClick={handleLookup}>
                {lookupLoading ? "ANALYSE..." : "LOOKUP"}
              </HudButton>
            </div>

            {lookupError && (
              <HudCard tone="alert" className="px-4 py-2 text-xs text-neon-pink">
                {lookupError}
              </HudCard>
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
          </HudCard>
        </StaggerItem>
      )}

      {/* SIGMA Rules Tab */}
      {activeTab === "sigma" && (
        <StaggerItem>
          <div className="space-y-4">
            {/* Import form */}
            <HudCard className="p-4 space-y-3">
              <h3 className="text-[10px] font-bold tracking-widest text-gray-500">IMPORTER UNE REGLE SIGMA</h3>
              <HudTextarea
                value={sigmaYaml}
                onChange={(e) => setSigmaYaml(e.target.value)}
                placeholder={"title: Detect Brute Force\nlogsource:\n  category: authentication\ndetection:\n  selection:\n    EventType: auth.fail\n  condition: selection\nlevel: medium"}
                rows={8}
              />
              {sigmaError && (
                <div className="text-xs text-red-400">{sigmaError}</div>
              )}
              <HudButton
                variant="primary"
                size="sm"
                loading={sigmaImporting}
                disabled={!sigmaYaml.trim()}
                onClick={handleImportSigma}
              >
                {sigmaImporting ? "IMPORT..." : "IMPORTER"}
              </HudButton>
            </HudCard>

            {/* Rules list */}
            <HudCard className="overflow-hidden p-0">
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
                          <HudBadge tone={rule.level === "high" ? "high" : rule.level === "medium" ? "medium" : "low"}>
                            {rule.level.toUpperCase()}
                          </HudBadge>
                        </td>
                        <td className="px-4 py-3">
                          <HudButton
                            size="sm"
                            variant={rule.enabled ? "matrix" : "ghost"}
                            onClick={() => handleToggle(rule.id, !rule.enabled)}
                          >
                            {rule.enabled ? "ACTIF" : "INACTIF"}
                          </HudButton>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <HudButton size="sm" variant="danger" onClick={() => handleDelete(rule.id)}>
                            SUPPRIMER
                          </HudButton>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </HudCard>
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
                  <HudStat label="CACHE TI" value={stats.cache_entries} />
                  <HudStat label="PROVIDERS" value={stats.providers_configured.length} />
                  <HudStat label="ABUSEIPDB" value={`${stats.abuseipdb_daily_used}/${stats.abuseipdb_daily_limit}`} />
                  <HudStat label="OTX" value={`${stats.otx_hourly_used}/${stats.otx_hourly_limit}`} />
                </div>

                <HudCard className="p-4 space-y-3">
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
                        <HudBadge key={p} tone="matrix">{p}</HudBadge>
                      ))}
                    </div>
                  )}
                </HudCard>
              </>
            ) : (
              <HudCard className="p-8 text-center">
                <p className="hud-label animate-pulse">LOADING STATS...</p>
              </HudCard>
            )}
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
