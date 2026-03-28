"use client";

import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { runRecon } from "@/lib/apiClient";
import type { ReconResult } from "@/lib/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text);
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { copyToClipboard(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="ml-2 px-1.5 py-0.5 text-[9px] font-mono border border-cyan-glow/20 rounded text-cyan-glow/60 hover:bg-cyan-glow/10 hover:text-cyan-glow transition-all"
    >
      {copied ? "COPIE" : "COPY"}
    </button>
  );
}

/** Card wrapper for each recon module. */
function ModuleCard({
  title, icon, count, children, defaultOpen = true,
}: {
  title: string; icon: string; count?: number; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const hasData = count === undefined || count > 0;
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel overflow-hidden"
    >
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between p-4 text-left hover:bg-cyan-glow/5 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className={`h-2 w-2 rounded-full ${hasData ? "bg-green-400 shadow-[0_0_6px_#4ade80]" : "bg-gray-600"}`} />
          <svg className="h-4 w-4 text-cyan-glow/70" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
          </svg>
          <span className="text-[10px] font-bold tracking-[0.2em] text-gray-300">{title}</span>
          {count !== undefined && (
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-glow/10 text-cyan-glow/70 font-mono">{count}</span>
          )}
        </div>
        <svg className={`h-3 w-3 text-gray-500 transition-transform ${open ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="border-t border-cyan-glow/10 p-4">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function KV({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value) return null;
  return (
    <div className="flex justify-between py-1 border-b border-white/5">
      <span className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</span>
      <span className="text-xs font-mono text-gray-300">{value}</span>
    </div>
  );
}

function Badge({ text, color = "cyan" }: { text: string; color?: string }) {
  const colors: Record<string, string> = {
    cyan: "bg-cyan-glow/10 text-cyan-glow border-cyan-glow/20",
    green: "bg-green-500/10 text-green-400 border-green-500/20",
    red: "bg-red-500/10 text-red-400 border-red-500/20",
    yellow: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    purple: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    blue: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  };
  return (
    <span className={`inline-block px-2 py-0.5 text-[9px] font-mono rounded border ${colors[color] || colors.cyan}`}>
      {text}
    </span>
  );
}

const DNS_COLORS: Record<string, string> = {
  A: "green", AAAA: "blue", MX: "purple", NS: "yellow", TXT: "cyan", CNAME: "blue", SOA: "red", SRV: "purple", CAA: "yellow",
};

// ---------------------------------------------------------------------------
// Terminal-style loading animation
// ---------------------------------------------------------------------------

function ScanAnimation() {
  const lines = [
    "[*] Initialisation du scan...",
    "[+] Resolution DNS en cours...",
    "[+] Enumeration des sous-domaines (crt.sh)...",
    "[+] Analyse WHOIS / RDAP...",
    "[+] Scan de ports TCP...",
    "[+] Fingerprint technologique...",
    "[+] Analyse certificat SSL/TLS...",
    "[+] Audit des headers HTTP...",
    "[+] Recherche Wayback Machine...",
    "[+] Harvesting d'emails...",
    "[+] Reverse IP lookup...",
    "[+] Generation des Google Dorks...",
    "[*] Compilation des resultats...",
  ];
  return (
    <div className="glass-panel p-6 font-mono text-xs space-y-1">
      <div className="flex items-center gap-2 mb-4">
        <div className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
        <span className="text-green-400 text-[10px] tracking-widest">SCAN EN COURS</span>
      </div>
      {lines.map((line, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.4, duration: 0.3 }}
          className={line.startsWith("[*]") ? "text-yellow-400" : "text-cyan-glow/70"}
        >
          {line}
          {i === lines.length - 1 && (
            <span className="inline-block w-2 h-3 bg-cyan-glow/60 ml-1 animate-pulse" />
          )}
        </motion.div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ReconPage() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ReconResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const handleScan = async (t?: string) => {
    const val = (t || target).trim();
    if (!val) return;
    setTarget(val);
    setLoading(true);
    setError(null);
    setResult(null);
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      const r = await runRecon(val, { signal: ac.signal });
      setResult(r);
    } catch (e: unknown) {
      if (e instanceof Error && e.name !== "AbortError") setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="hud-heading text-lg tracking-widest text-cyan-glow">OSINT RECON</h1>
        <p className="text-xs text-gray-500 mt-1">Reconnaissance offensive — Collecte d'informations sur une cible</p>
      </div>

      {/* Input */}
      <div className="glass-panel p-4">
        <form
          onSubmit={(e) => { e.preventDefault(); handleScan(); }}
          className="flex gap-3"
        >
          <div className="relative flex-1">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-cyan-glow/40 font-mono text-xs">$&gt;</span>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="domaine.com ou 192.168.1.1"
              className="w-full rounded border border-cyan-glow/20 bg-space-dark/80 py-2.5 pl-9 pr-4 text-sm font-mono text-gray-200 placeholder-gray-600 outline-none focus:border-cyan-glow/50 focus:shadow-cyan-sm transition-all"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !target.trim()}
            className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-[0.2em] text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-sm disabled:opacity-30"
          >
            {loading ? "SCANNING..." : "LANCER RECON"}
          </button>
        </form>

        {/* Quick targets */}
        {!result && !loading && (
          <div className="flex gap-2 mt-3">
            <span className="text-[9px] text-gray-600 pt-1">Exemples :</span>
            {["google.com", "github.com", "example.com"].map((d) => (
              <button
                key={d}
                onClick={() => handleScan(d)}
                className="text-[10px] font-mono text-cyan-glow/50 hover:text-cyan-glow border border-cyan-glow/10 rounded px-2 py-0.5 hover:bg-cyan-glow/5 transition-all"
              >
                {d}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="glass-panel border-red-500/30 p-4 text-xs text-red-400 font-mono">
          [ERROR] {error}
        </div>
      )}

      {/* Loading */}
      {loading && <ScanAnimation />}

      {/* Results */}
      {result && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="space-y-3"
        >
          {/* Target summary */}
          <div className="glass-panel p-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="h-10 w-10 rounded-lg border border-cyan-glow/20 bg-cyan-glow/5 flex items-center justify-center">
                <svg className="h-5 w-5 text-cyan-glow" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-mono text-white">{result.target}</p>
                <div className="flex items-center gap-2 mt-0.5">
                  <Badge text={result.target_type.toUpperCase()} />
                  {result.resolved_ip && <span className="text-[10px] font-mono text-gray-500">{result.resolved_ip}</span>}
                </div>
              </div>
            </div>
            <div className="text-right">
              <p className="text-[9px] text-gray-500 tracking-wider">DUREE DU SCAN</p>
              <p className="text-sm font-mono text-cyan-glow">{(result.scan_duration_ms / 1000).toFixed(1)}s</p>
            </div>
          </div>

          {/* Modules grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">

            {/* WHOIS */}
            {result.whois && (
              <ModuleCard title="WHOIS" icon="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z">
                <div className="space-y-0.5">
                  {Object.entries(result.whois).map(([k, v]) => (
                    <KV key={k} label={k} value={Array.isArray(v) ? (v as string[]).join(", ") : String(v ?? "")} />
                  ))}
                </div>
              </ModuleCard>
            )}

            {/* DNS Records */}
            {result.dns_records && Object.keys(result.dns_records).length > 0 && (
              <ModuleCard title="DNS RECORDS" icon="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z" count={Object.keys(result.dns_records).length}>
                <div className="space-y-2">
                  {Object.entries(result.dns_records).map(([type, records]) => (
                    <div key={type}>
                      <Badge text={type} color={DNS_COLORS[type] || "cyan"} />
                      <div className="mt-1 space-y-0.5 ml-2">
                        {(records as string[]).map((r, i) => (
                          <p key={i} className="text-[10px] font-mono text-gray-400 break-all">{r}</p>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </ModuleCard>
            )}

            {/* Subdomains */}
            {result.subdomains && result.subdomains.length > 0 && (
              <ModuleCard title="SOUS-DOMAINES" icon="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582" count={result.subdomains.length}>
                <div className="max-h-60 overflow-y-auto space-y-0.5">
                  {result.subdomains.map((s, i) => (
                    <div key={i} className="flex justify-between py-1 border-b border-white/5">
                      <span className="text-[10px] font-mono text-cyan-glow/80">{s.subdomain}</span>
                      <span className="text-[10px] font-mono text-gray-500">{s.ip || "—"}</span>
                    </div>
                  ))}
                </div>
              </ModuleCard>
            )}

            {/* Reverse IP */}
            {result.reverse_ip && result.reverse_ip.length > 0 && (
              <ModuleCard title="REVERSE IP" icon="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" count={result.reverse_ip.length}>
                <div className="max-h-48 overflow-y-auto space-y-0.5">
                  {result.reverse_ip.map((d, i) => (
                    <p key={i} className="text-[10px] font-mono text-gray-400 py-0.5 border-b border-white/5">{d}</p>
                  ))}
                </div>
              </ModuleCard>
            )}

            {/* GeoIP */}
            {result.geo && (
              <ModuleCard title="GEOLOCALISATION" icon="M15 10.5a3 3 0 11-6 0 3 3 0 016 0z M19.5 10.5c0 7.142-7.5 11.25-7.5 11.25S4.5 17.642 4.5 10.5a7.5 7.5 0 1115 0z">
                <div className="space-y-0.5">
                  <KV label="Pays" value={String(result.geo.country ?? "")} />
                  <KV label="Ville" value={String(result.geo.city ?? "")} />
                  <KV label="Region" value={String(result.geo.regionName ?? "")} />
                  <KV label="ISP" value={String(result.geo.isp ?? "")} />
                  <KV label="Org" value={String(result.geo.org ?? "")} />
                  <KV label="ASN" value={String(result.geo.as ?? "")} />
                  <KV label="Timezone" value={String(result.geo.timezone ?? "")} />
                  {result.geo.lat && result.geo.lon ? (
                    <KV label="Coords" value={`${String(result.geo.lat)}, ${String(result.geo.lon)}`} />
                  ) : null}
                </div>
              </ModuleCard>
            )}

            {/* Tech Stack */}
            {result.tech_stack && (
              <ModuleCard title="STACK TECHNIQUE" icon="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5">
                <div className="space-y-2">
                  <KV label="Serveur" value={result.tech_stack.server} />
                  <KV label="Framework" value={result.tech_stack.framework} />
                  <KV label="CMS" value={result.tech_stack.cms} />
                  <KV label="CDN" value={result.tech_stack.cdn} />
                  <KV label="Langage" value={result.tech_stack.language} />
                  {result.tech_stack.detected.length > 0 && (
                    <div className="pt-2">
                      <p className="text-[9px] text-gray-500 uppercase tracking-wider mb-1">Technologies detectees</p>
                      <div className="flex flex-wrap gap-1">
                        {result.tech_stack.detected.map((t) => (
                          <Badge key={t} text={t} color="green" />
                        ))}
                      </div>
                    </div>
                  )}
                  {result.tech_stack.cookies.length > 0 && (
                    <div className="pt-2">
                      <p className="text-[9px] text-gray-500 uppercase tracking-wider mb-1">Cookies</p>
                      <div className="flex flex-wrap gap-1">
                        {result.tech_stack.cookies.map((c) => (
                          <Badge key={c} text={c} color="yellow" />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </ModuleCard>
            )}

            {/* SSL Certificate */}
            {result.ssl_cert && (
              <ModuleCard title="CERTIFICAT SSL/TLS" icon="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z">
                <div className="space-y-0.5">
                  <KV label="Subject" value={result.ssl_cert.subject} />
                  <KV label="Issuer" value={result.ssl_cert.issuer} />
                  <KV label="Protocole" value={result.ssl_cert.protocol} />
                  <KV label="Cipher" value={result.ssl_cert.cipher} />
                  <KV label="Cle" value={result.ssl_cert.key_size ? `${result.ssl_cert.key_size} bits` : null} />
                  <KV label="Debut" value={result.ssl_cert.not_before} />
                  <KV label="Expiration" value={result.ssl_cert.not_after} />
                  {result.ssl_cert.days_remaining !== null && (
                    <div className="flex justify-between py-1 border-b border-white/5">
                      <span className="text-[10px] text-gray-500 uppercase tracking-wider">Jours restants</span>
                      <span className={`text-xs font-mono font-bold ${
                        result.ssl_cert.days_remaining > 30 ? "text-green-400" :
                        result.ssl_cert.days_remaining > 7 ? "text-yellow-400" : "text-red-400"
                      }`}>
                        {result.ssl_cert.days_remaining}
                        {result.ssl_cert.is_expired && " (EXPIRE)"}
                      </span>
                    </div>
                  )}
                  {result.ssl_cert.san.length > 0 && (
                    <div className="pt-2">
                      <p className="text-[9px] text-gray-500 uppercase tracking-wider mb-1">SAN ({result.ssl_cert.san.length})</p>
                      <div className="max-h-24 overflow-y-auto space-y-0.5">
                        {result.ssl_cert.san.map((s) => (
                          <p key={s} className="text-[10px] font-mono text-gray-400">{s}</p>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </ModuleCard>
            )}

            {/* Security Headers */}
            {result.headers && (
              <ModuleCard title="HEADERS DE SECURITE" icon="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z">
                <div className="space-y-3">
                  {/* Score bar */}
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-[10px] text-gray-500">Score de securite</span>
                      <span className={`text-xs font-mono font-bold ${
                        result.headers.security_score >= result.headers.max_score * 0.7 ? "text-green-400" :
                        result.headers.security_score >= result.headers.max_score * 0.4 ? "text-yellow-400" : "text-red-400"
                      }`}>
                        {result.headers.security_score}/{result.headers.max_score}
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-gray-800 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${
                          result.headers.security_score >= result.headers.max_score * 0.7 ? "bg-green-500" :
                          result.headers.security_score >= result.headers.max_score * 0.4 ? "bg-yellow-500" : "bg-red-500"
                        }`}
                        style={{ width: `${(result.headers.security_score / result.headers.max_score) * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Header list */}
                  <div className="space-y-1">
                    {result.headers.details.map((d) => (
                      <div key={d.header} className="flex items-center justify-between py-1 border-b border-white/5">
                        <div className="flex items-center gap-2">
                          <span className={`text-xs ${d.present ? "text-green-400" : "text-red-400"}`}>
                            {d.present ? "\u2713" : "\u2717"}
                          </span>
                          <span className="text-[10px] font-mono text-gray-400">{d.header}</span>
                        </div>
                        <span className="text-[9px] text-gray-600">{d.points}pts</span>
                      </div>
                    ))}
                  </div>
                </div>
              </ModuleCard>
            )}

            {/* Open Ports */}
            {result.open_ports.length > 0 && (
              <ModuleCard title="PORTS OUVERTS" icon="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m9.07-9.07l-1.757 1.757a4.5 4.5 0 010 6.364l-4.5 4.5a4.5 4.5 0 01-6.364 0" count={result.open_ports.length}>
                <div className="space-y-0.5">
                  <div className="grid grid-cols-3 gap-2 pb-1 border-b border-cyan-glow/20 mb-1">
                    <span className="text-[9px] font-bold text-gray-500 tracking-wider">PORT</span>
                    <span className="text-[9px] font-bold text-gray-500 tracking-wider">SERVICE</span>
                    <span className="text-[9px] font-bold text-gray-500 tracking-wider">ETAT</span>
                  </div>
                  {result.open_ports.map((p) => (
                    <div key={p.port} className="grid grid-cols-3 gap-2 py-0.5">
                      <span className="text-xs font-mono text-cyan-glow">{p.port}</span>
                      <span className="text-[10px] font-mono text-gray-400">{p.service}</span>
                      <Badge text={p.state.toUpperCase()} color={p.state === "open" ? "green" : "red"} />
                    </div>
                  ))}
                </div>
              </ModuleCard>
            )}

            {/* Wayback Machine */}
            {result.wayback && result.wayback.snapshots_count > 0 && (
              <ModuleCard title="WAYBACK MACHINE" icon="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" count={result.wayback.snapshots_count}>
                <div className="space-y-2">
                  <div className="flex gap-4">
                    <KV label="Premier snapshot" value={result.wayback.first_seen} />
                    <KV label="Dernier snapshot" value={result.wayback.last_seen} />
                  </div>
                  <div className="max-h-48 overflow-y-auto space-y-0.5">
                    {result.wayback.urls.map((u, i) => (
                      <div key={i} className="flex items-center gap-2 py-0.5 border-b border-white/5">
                        <Badge text={u.status || "?"} color={u.status === "200" ? "green" : "yellow"} />
                        <span className="text-[10px] font-mono text-gray-400 truncate flex-1">{u.url}</span>
                        <span className="text-[9px] text-gray-600">{u.timestamp}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </ModuleCard>
            )}

            {/* Emails Found */}
            {result.emails_found.length > 0 && (
              <ModuleCard title="EMAILS TROUVES" icon="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" count={result.emails_found.length}>
                <div className="space-y-1">
                  {result.emails_found.map((email) => (
                    <div key={email} className="flex items-center justify-between py-1 border-b border-white/5">
                      <span className="text-[10px] font-mono text-cyan-glow/80">{email}</span>
                      <CopyBtn text={email} />
                    </div>
                  ))}
                </div>
              </ModuleCard>
            )}

            {/* Robots & Sitemap */}
            {result.robots_sitemap && (
              <ModuleCard title="ROBOTS.TXT & SITEMAP" icon="M3.75 9.776c.112-.017.227-.026.344-.026h15.812c.117 0 .232.009.344.026m-16.5 0a2.25 2.25 0 00-1.883 2.542l.857 6a2.25 2.25 0 002.227 1.932H19.05a2.25 2.25 0 002.227-1.932l.857-6a2.25 2.25 0 00-1.883-2.542m-16.5 0V6A2.25 2.25 0 016 3.75h3.879a1.5 1.5 0 011.06.44l2.122 2.12a1.5 1.5 0 001.06.44H18A2.25 2.25 0 0120.25 9v.776">
                <div className="space-y-3">
                  {result.robots_sitemap.disallowed.length > 0 && (
                    <div>
                      <p className="text-[9px] text-gray-500 uppercase tracking-wider mb-1">Chemins bloques ({result.robots_sitemap.disallowed.length})</p>
                      <div className="flex flex-wrap gap-1">
                        {result.robots_sitemap.disallowed.map((p) => (
                          <Badge key={p} text={p} color="red" />
                        ))}
                      </div>
                    </div>
                  )}
                  {result.robots_sitemap.sitemaps.length > 0 && (
                    <div>
                      <p className="text-[9px] text-gray-500 uppercase tracking-wider mb-1">Sitemaps</p>
                      {result.robots_sitemap.sitemaps.map((s) => (
                        <p key={s} className="text-[10px] font-mono text-cyan-glow/70 break-all">{s}</p>
                      ))}
                    </div>
                  )}
                  {result.robots_sitemap.robots_txt ? (
                    <details>
                      <summary className="text-[9px] text-gray-500 cursor-pointer hover:text-gray-400">Voir robots.txt brut</summary>
                      <pre className="mt-1 text-[9px] font-mono text-gray-500 bg-black/30 rounded p-2 max-h-40 overflow-auto whitespace-pre-wrap">{result.robots_sitemap.robots_txt}</pre>
                    </details>
                  ) : null}
                </div>
              </ModuleCard>
            )}
          </div>

          {/* Google Dorks — full width */}
          {result.google_dorks.length > 0 && (
            <ModuleCard title="GOOGLE DORKS" icon="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" count={result.google_dorks.length} defaultOpen={false}>
              <div className="space-y-2">
                {result.google_dorks.map((dork, i) => (
                  <div key={i} className="flex items-start justify-between gap-2 py-1.5 border-b border-white/5">
                    <div className="flex-1 min-w-0">
                      <p className="text-[10px] text-gray-400 mb-0.5">{dork.label}</p>
                      <p className="text-[10px] font-mono text-cyan-glow/70 break-all">{dork.query}</p>
                    </div>
                    <CopyBtn text={dork.query} />
                  </div>
                ))}
              </div>
            </ModuleCard>
          )}

          {/* Errors */}
          {result.errors.length > 0 && (
            <ModuleCard title="ERREURS" icon="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" count={result.errors.length}>
              <div className="space-y-1">
                {result.errors.map((e, i) => (
                  <p key={i} className="text-[10px] font-mono text-red-400/80">[!] {e}</p>
                ))}
              </div>
            </ModuleCard>
          )}
        </motion.div>
      )}
    </div>
  );
}
