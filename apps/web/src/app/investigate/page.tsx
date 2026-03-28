"use client";

import { useState } from "react";
import Link from "next/link";
import { investigate } from "@/lib/apiClient";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import type { InvestigateResult } from "@/lib/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/15 border-red-500/30",
  high: "text-orange-400 bg-orange-500/15 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/15 border-yellow-500/30",
  low: "text-green-400 bg-green-500/15 border-green-500/30",
};

export default function InvestigatePage() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<InvestigateResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async () => {
    const t = target.trim();
    if (!t) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await investigate(t);
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erreur d'investigation");
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Investigation
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            OSINT // IP & DOMAIN INTELLIGENCE
          </p>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Search bar */}
      <StaggerItem>
        <div className="glass-panel p-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              placeholder="Entrer une adresse IP ou un domaine (ex: 8.8.8.8, google.com)"
              className="flex-1 rounded-md border border-gray-700 bg-gray-900/80 px-4 py-3 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none"
            />
            <button
              onClick={handleSearch}
              disabled={loading}
              className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-8 py-3 text-xs font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50"
            >
              {loading ? "ANALYSE..." : "INVESTIGUER"}
            </button>
          </div>
        </div>
      </StaggerItem>

      {error && (
        <StaggerItem>
          <div className="glass-panel border-red-500/30 px-4 py-3 text-xs text-red-400">
            <span className="mr-2 text-red-500">&#x25B2;</span>{error}
          </div>
        </StaggerItem>
      )}

      {loading && (
        <StaggerItem>
          <div className="flex h-40 items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <div className="relative h-12 w-12">
                <div className="absolute inset-0 rounded-full border-2 border-cyan-glow/20 animate-ping" />
                <div className="absolute inset-2 rounded-full border-2 border-t-cyan-glow border-transparent animate-spin" />
              </div>
              <p className="hud-label animate-pulse">INVESTIGATION EN COURS...</p>
            </div>
          </div>
        </StaggerItem>
      )}

      {result && !loading && (
        <>
          {/* Header card */}
          <StaggerItem>
            <div className="glass-panel p-5">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-lg font-bold font-mono text-white">{result.target}</p>
                  <div className="flex items-center gap-3 mt-1">
                    <span className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-2 py-0.5 text-[10px] font-bold text-cyan-glow uppercase">
                      {result.target_type}
                    </span>
                    {result.resolved_ip && result.target_type === "domain" && (
                      <span className="text-xs text-gray-400 font-mono">
                        → {result.resolved_ip}
                      </span>
                    )}
                    {result.reverse_dns && (
                      <span className="text-xs text-gray-500 font-mono">
                        PTR: {result.reverse_dns}
                      </span>
                    )}
                  </div>
                </div>

                {/* Threat score badge */}
                {result.threat_score && (
                  <div
                    className={`rounded-lg px-4 py-2 text-center border ${
                      result.threat_score.score >= 70
                        ? "bg-red-500/15 border-red-500/30"
                        : result.threat_score.score >= 40
                          ? "bg-yellow-500/15 border-yellow-500/30"
                          : "bg-green-500/15 border-green-500/30"
                    }`}
                  >
                    <p
                      className={`text-2xl font-bold font-mono ${
                        result.threat_score.score >= 70
                          ? "text-red-400"
                          : result.threat_score.score >= 40
                            ? "text-yellow-400"
                            : "text-green-400"
                      }`}
                    >
                      {result.threat_score.score}
                    </p>
                    <p className="text-[9px] tracking-widest text-gray-500">THREAT SCORE</p>
                  </div>
                )}
              </div>
            </div>
          </StaggerItem>

          {/* KPIs row */}
          <StaggerItem>
            <div className="grid grid-cols-4 gap-3">
              <div className="glass-panel p-3 text-center">
                <p className="text-xl font-bold font-mono text-cyan-glow">{result.event_count}</p>
                <p className="text-[9px] tracking-widest text-gray-500 mt-0.5">EVENTS</p>
              </div>
              <div className="glass-panel p-3 text-center">
                <p className="text-xl font-bold font-mono text-cyan-glow">{result.incident_count}</p>
                <p className="text-[9px] tracking-widest text-gray-500 mt-0.5">INCIDENTS</p>
              </div>
              <div className="glass-panel p-3 text-center">
                <p className="text-xl font-bold font-mono text-cyan-glow">{result.related_users.length}</p>
                <p className="text-[9px] tracking-widest text-gray-500 mt-0.5">UTILISATEURS</p>
              </div>
              <div className="glass-panel p-3 text-center">
                <p className="text-xl font-bold font-mono text-cyan-glow">{result.event_types.length}</p>
                <p className="text-[9px] tracking-widest text-gray-500 mt-0.5">TYPES</p>
              </div>
            </div>
          </StaggerItem>

          {/* Two columns layout */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Left column */}
            <div className="space-y-4">
              {/* GeoIP */}
              {result.geo && (
                <StaggerItem>
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">GEOLOCALISATION</h3>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      {Object.entries(result.geo).map(([key, val]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-gray-500 uppercase">{key}</span>
                          <span className="text-gray-300 font-mono">{String(val)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </StaggerItem>
              )}

              {/* DNS */}
              {result.dns && Object.keys(result.dns).length > 0 && (
                <StaggerItem>
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">DNS</h3>
                    <div className="space-y-2">
                      {Object.entries(result.dns).map(([rtype, records]) => (
                        <div key={rtype}>
                          <span className="text-[10px] font-bold text-cyan-glow">{rtype}</span>
                          <div className="ml-2">
                            {(records as string[]).map((r, i) => (
                              <p key={i} className="text-xs text-gray-300 font-mono">{r}</p>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </StaggerItem>
              )}

              {/* WHOIS */}
              {result.whois && (
                <StaggerItem>
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">WHOIS</h3>
                    <div className="space-y-1.5 text-xs">
                      {result.whois.registrar && (
                        <div className="flex justify-between">
                          <span className="text-gray-500">Registrar</span>
                          <span className="text-gray-300">{result.whois.registrar}</span>
                        </div>
                      )}
                      {result.whois.org && (
                        <div className="flex justify-between">
                          <span className="text-gray-500">Organisation</span>
                          <span className="text-gray-300">{result.whois.org}</span>
                        </div>
                      )}
                      {result.whois.country && (
                        <div className="flex justify-between">
                          <span className="text-gray-500">Pays</span>
                          <span className="text-gray-300">{result.whois.country}</span>
                        </div>
                      )}
                      {result.whois.creation_date && (
                        <div className="flex justify-between">
                          <span className="text-gray-500">Creation</span>
                          <span className="text-gray-300 font-mono">{result.whois.creation_date}</span>
                        </div>
                      )}
                      {result.whois.expiration_date && (
                        <div className="flex justify-between">
                          <span className="text-gray-500">Expiration</span>
                          <span className="text-gray-300 font-mono">{result.whois.expiration_date}</span>
                        </div>
                      )}
                      {result.whois.name_servers && result.whois.name_servers.length > 0 && (
                        <div>
                          <span className="text-gray-500">Serveurs DNS</span>
                          <div className="ml-2 mt-0.5">
                            {result.whois.name_servers.map((ns, i) => (
                              <p key={i} className="text-gray-300 font-mono text-[11px]">{ns}</p>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </StaggerItem>
              )}

              {/* Threat Intelligence */}
              {result.threat_intel && (
                <StaggerItem>
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">THREAT INTELLIGENCE</h3>
                    <div className="flex items-center gap-3 mb-3">
                      <span
                        className={`rounded-full px-3 py-1 text-sm font-bold font-mono ${
                          result.threat_intel.risk_score >= 70
                            ? "bg-red-500/15 text-red-400"
                            : result.threat_intel.risk_score >= 30
                              ? "bg-yellow-500/15 text-yellow-400"
                              : "bg-green-500/15 text-green-400"
                        }`}
                      >
                        {result.threat_intel.risk_score}/100
                      </span>
                      <span
                        className={`text-xs font-bold ${
                          result.threat_intel.is_malicious ? "text-red-400" : "text-green-400"
                        }`}
                      >
                        {result.threat_intel.is_malicious ? "MALICIOUS" : "CLEAN"}
                      </span>
                    </div>
                    {result.threat_intel.tags && result.threat_intel.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {result.threat_intel.tags.map((tag) => (
                          <span
                            key={tag}
                            className="rounded-full border border-cyan-glow/20 bg-cyan-glow/5 px-2 py-0.5 text-[10px] text-cyan-glow"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </StaggerItem>
              )}
            </div>

            {/* Right column */}
            <div className="space-y-4">
              {/* Timeline */}
              {result.timeline.length > 0 && (
                <StaggerItem>
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">
                      ACTIVITE 24H
                    </h3>
                    <div className="flex items-end gap-px h-20">
                      {result.timeline.map((t) => {
                        const maxCount = Math.max(...result.timeline.map((x) => x.count), 1);
                        const pct = (t.count / maxCount) * 100;
                        return (
                          <div
                            key={t.hour}
                            className="flex-1 bg-cyan-glow/30 hover:bg-cyan-glow/50 transition-colors rounded-t-sm"
                            style={{ height: `${Math.max(pct, 2)}%` }}
                            title={`${t.hour}: ${t.count} events`}
                          />
                        );
                      })}
                    </div>
                    <div className="flex justify-between mt-1">
                      <span className="text-[9px] text-gray-600">-24h</span>
                      <span className="text-[9px] text-gray-600">maintenant</span>
                    </div>
                  </div>
                </StaggerItem>
              )}

              {/* Event types */}
              {result.event_types.length > 0 && (
                <StaggerItem>
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">TYPES D&apos;EVENTS</h3>
                    <div className="space-y-1.5">
                      {result.event_types.map((et) => {
                        const maxC = Math.max(...result.event_types.map((x) => x.count), 1);
                        const pct = (et.count / maxC) * 100;
                        return (
                          <div key={et.type} className="flex items-center gap-2">
                            <span className="text-[11px] text-gray-400 font-mono w-32 truncate">{et.type}</span>
                            <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-cyan-glow/60 rounded-full"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                            <span className="text-[10px] text-gray-500 font-mono w-8 text-right">{et.count}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </StaggerItem>
              )}

              {/* Related users */}
              {result.related_users.length > 0 && (
                <StaggerItem>
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">UTILISATEURS ASSOCIES</h3>
                    <div className="space-y-1.5">
                      {result.related_users.map((u) => (
                        <div key={u.username} className="flex items-center justify-between">
                          <span className="text-xs text-gray-300 font-mono">{u.username}</span>
                          <span className="text-[10px] text-gray-500">{u.event_count} events</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </StaggerItem>
              )}

              {/* Recent incidents */}
              {result.recent_incidents.length > 0 && (
                <StaggerItem>
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">INCIDENTS LIES</h3>
                    <div className="space-y-2">
                      {result.recent_incidents.map((inc) => (
                        <Link
                          key={inc.id}
                          href={`/incidents/${inc.id}`}
                          className="block rounded border border-gray-800 p-2 hover:border-cyan-glow/20 transition-colors"
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-xs text-gray-200 truncate">{inc.title}</span>
                            <span
                              className={`rounded px-1.5 py-0.5 text-[9px] font-bold border ${
                                SEVERITY_COLORS[inc.severity] || SEVERITY_COLORS.low
                              }`}
                            >
                              {inc.severity.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-[10px] text-gray-500 mt-0.5">
                            {inc.status} — {new Date(inc.created_at).toLocaleDateString("fr-FR")}
                          </p>
                        </Link>
                      ))}
                    </div>
                  </div>
                </StaggerItem>
              )}
            </div>
          </div>

          {/* Recent events table */}
          {result.recent_events.length > 0 && (
            <StaggerItem>
              <div className="glass-panel overflow-hidden">
                <div className="px-4 py-3 border-b border-cyan-glow/10">
                  <h3 className="text-[10px] font-bold tracking-widest text-gray-500">
                    EVENTS RECENTS ({result.recent_events.length})
                  </h3>
                </div>
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-gray-800/50">
                      <th className="px-4 py-2 text-[9px] font-bold tracking-widest text-gray-500">DATE</th>
                      <th className="px-4 py-2 text-[9px] font-bold tracking-widest text-gray-500">TYPE</th>
                      <th className="px-4 py-2 text-[9px] font-bold tracking-widest text-gray-500">SEVERITE</th>
                      <th className="px-4 py-2 text-[9px] font-bold tracking-widest text-gray-500">UTILISATEUR</th>
                      <th className="px-4 py-2 text-[9px] font-bold tracking-widest text-gray-500">MESSAGE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.recent_events.map((ev) => (
                      <tr key={ev.id} className="border-b border-gray-800/30 hover:bg-cyan-glow/5">
                        <td className="px-4 py-2 text-[11px] text-gray-400 font-mono whitespace-nowrap">
                          {new Date(ev.ts).toLocaleString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit", day: "2-digit", month: "2-digit" })}
                        </td>
                        <td className="px-4 py-2 text-[11px] text-cyan-glow font-mono">{ev.event_type}</td>
                        <td className="px-4 py-2">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[9px] font-bold border ${
                              SEVERITY_COLORS[ev.severity] || SEVERITY_COLORS.low
                            }`}
                          >
                            {ev.severity.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-[11px] text-gray-400 font-mono">{ev.username || "—"}</td>
                        <td className="px-4 py-2 text-[11px] text-gray-500 truncate max-w-xs">{ev.message || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </StaggerItem>
          )}

          {/* No data state */}
          {result.event_count === 0 && !result.geo && !result.dns && !result.whois && (
            <StaggerItem>
              <div className="glass-panel p-8 text-center">
                <p className="text-sm text-gray-400">Aucune donnee trouvee pour cette cible</p>
                <p className="text-[10px] text-gray-600 mt-1">
                  Cette IP/domaine n&apos;a pas encore ete observe dans le SIEM
                </p>
              </div>
            </StaggerItem>
          )}
        </>
      )}

      {/* Empty state */}
      {!result && !loading && !error && (
        <StaggerItem>
          <div className="glass-panel p-12 text-center space-y-4">
            <div className="flex justify-center">
              <svg className="h-16 w-16 text-cyan-glow/20" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m5.231 13.481L15 17.25m-4.5-15H5.625c-.621 0-1.125.504-1.125 1.125v16.5c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9zm3.75 11.625a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
              </svg>
            </div>
            <div>
              <p className="text-sm text-gray-400">Entrer une IP ou un domaine pour lancer l&apos;investigation</p>
              <p className="text-[10px] text-gray-600 mt-1">
                GeoIP, DNS, WHOIS, Threat Intelligence, events SIEM, incidents, timeline
              </p>
            </div>
            <div className="flex flex-wrap justify-center gap-2 mt-4">
              {["8.8.8.8", "1.1.1.1", "google.com", "185.220.101.1"].map((ex) => (
                <button
                  key={ex}
                  onClick={() => { setTarget(ex); }}
                  className="rounded border border-gray-700 px-3 py-1 text-[10px] font-mono text-gray-500 hover:border-cyan-glow/30 hover:text-cyan-glow transition-colors"
                >
                  {ex}
                </button>
              ))}
            </div>
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
