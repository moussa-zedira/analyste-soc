"use client";

import { useCallback, useRef, useState } from "react";
import { motion } from "framer-motion";
import { scanTarget } from "@/lib/apiClient";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import type { ScannerResult } from "@/lib/types";

/* ---------- helpers ---------- */

function scoreColor(score: number): string {
  if (score < 40) return "#ef4444";
  if (score < 70) return "#f59e0b";
  return "#00E5FF";
}

function scoreLabel(score: number): string {
  if (score < 40) return "CRITICAL";
  if (score < 70) return "WARNING";
  return "SECURE";
}

function val(obj: Record<string, unknown> | null | undefined, key: string): string {
  if (!obj) return "N/A";
  const v = obj[key];
  if (v === null || v === undefined) return "N/A";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function entries(obj: Record<string, unknown> | null | undefined): [string, string][] {
  if (!obj) return [];
  return Object.entries(obj).map(([k, v]) => [
    k,
    v === null || v === undefined ? "N/A" : typeof v === "object" ? JSON.stringify(v) : String(v),
  ]);
}

/* ---------- Score Gauge SVG ---------- */

function ScoreGauge({ score }: { score: number }) {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = scoreColor(score);

  return (
    <div className="relative flex flex-col items-center">
      <svg width="180" height="180" viewBox="0 0 180 180">
        {/* Background circle */}
        <circle
          cx="90"
          cy="90"
          r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth="10"
        />
        {/* Score arc */}
        <motion.circle
          cx="90"
          cy="90"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.2, ease: "easeOut" }}
          transform="rotate(-90 90 90)"
          style={{ filter: `drop-shadow(0 0 8px ${color})` }}
        />
        {/* Score number */}
        <text
          x="90"
          y="85"
          textAnchor="middle"
          fill={color}
          fontSize="36"
          fontWeight="700"
          fontFamily="Orbitron, monospace"
        >
          {score}
        </text>
        <text
          x="90"
          y="108"
          textAnchor="middle"
          fill={color}
          fontSize="10"
          fontWeight="500"
          opacity={0.7}
          letterSpacing="3"
        >
          {scoreLabel(score)}
        </text>
      </svg>
    </div>
  );
}

/* ---------- Card wrapper ---------- */

function Card({
  title,
  icon,
  children,
  className = "",
  delay = 0,
}: {
  title: string;
  icon: string;
  children: React.ReactNode;
  className?: string;
  delay?: number;
}) {
  return (
    <motion.div
      className={`glass-panel glass-panel-animated p-5 ${className}`}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay, ease: "easeOut" }}
    >
      <div className="mb-4 flex items-center gap-2">
        <svg
          className="h-4 w-4 text-cyan-glow"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          strokeWidth={1.5}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
        </svg>
        <h3 className="hud-heading text-xs font-bold tracking-widest text-cyan-glow">
          {title}
        </h3>
      </div>
      {children}
    </motion.div>
  );
}

/* ---------- Table rows helper ---------- */

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between border-b border-cyan-glow/5 py-1.5 last:border-0">
      <span className="text-[10px] tracking-wider text-gray-500 uppercase">{label}</span>
      <span className="ml-4 text-right text-[11px] text-gray-300 font-mono break-all max-w-[60%]">
        {value}
      </span>
    </div>
  );
}

/* ---------- Security header check ---------- */

const SECURITY_HEADERS = [
  { key: "strict-transport-security", label: "HSTS" },
  { key: "x-frame-options", label: "X-Frame-Options" },
  { key: "content-security-policy", label: "CSP" },
  { key: "x-content-type-options", label: "X-Content-Type-Options" },
  { key: "x-xss-protection", label: "X-XSS-Protection" },
];

/* ---------- Main page component ---------- */

export default function ScannerPage() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<ScannerResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const handleScan = useCallback(async () => {
    const trimmed = target.trim();
    if (!trimmed) return;

    // Abort previous scan
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await scanTarget(trimmed, { signal: controller.signal });
      setResult(data);
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }, [target]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleScan();
    },
    [handleScan],
  );

  return (
    <PageTransition className="space-y-6">
      {/* Header */}
      <StaggerItem>
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            URL / Domain Scanner
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            SECURITY ANALYSIS // RECONNAISSANCE MODULE
          </p>
        </div>
      </StaggerItem>

      <StaggerItem>
        <div className="cyan-line" />
      </StaggerItem>

      {/* Search bar */}
      <StaggerItem>
        <div className="glass-panel glass-panel-animated flex items-center gap-3 p-3">
          {/* Search icon */}
          <svg
            className="h-5 w-5 flex-shrink-0 text-cyan-glow/50"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"
            />
          </svg>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Entrez un domaine ou une URL..."
            className="flex-1 bg-transparent text-sm text-gray-200 placeholder-gray-600 outline-none font-mono tracking-wide"
          />
          <button
            onClick={handleScan}
            disabled={loading || !target.trim()}
            className="flex items-center gap-2 rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-5 py-2.5 text-[11px] font-bold tracking-widest text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-md active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {loading && (
              <svg
                className="h-4 w-4 animate-spin"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                />
              </svg>
            )}
            {loading ? "SCAN EN COURS..." : "ANALYSER"}
          </button>
        </div>
      </StaggerItem>

      {/* Error */}
      {error && (
        <StaggerItem>
          <div className="glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400">
            <span className="mr-2 text-red-500">&#x25B2;</span>
            {error}
          </div>
        </StaggerItem>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Score Card - full width */}
          <Card
            title="Security Score"
            icon="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
            className="col-span-full"
            delay={0.1}
          >
            <div className="flex flex-col items-center gap-6 md:flex-row md:items-start">
              <ScoreGauge score={result.security_score} />
              <div className="flex-1 space-y-2">
                <div className="mb-3 flex items-center gap-2">
                  <span className="font-mono text-sm text-gray-300">{result.target}</span>
                  <span className="text-[10px] tracking-wider text-gray-600">
                    {result.scan_duration_ms}ms
                  </span>
                </div>
                <div className="space-y-1">
                  {result.score_details.map((detail, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 text-[11px]"
                    >
                      <span
                        className={
                          detail.passed ? "text-emerald-400" : "text-red-400"
                        }
                      >
                        {detail.passed ? "\u2713" : "\u2717"}
                      </span>
                      <span className="text-gray-400">{detail.check}</span>
                      <span
                        className={`ml-auto font-mono text-[10px] ${
                          detail.passed
                            ? "text-emerald-400/70"
                            : "text-red-400/70"
                        }`}
                      >
                        {detail.passed ? "+" : ""}{detail.points}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Card>

          {/* Grid of cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {/* DNS Card */}
            <Card
              title="DNS Records"
              icon="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7"
              delay={0.2}
            >
              <div className="space-y-0.5">
                <InfoRow label="Resolved IP" value={result.resolved_ip ?? "N/A"} />
                {result.dns && (
                  <>
                    {result.dns.a && (
                      <InfoRow label="A Records" value={Array.isArray(result.dns.a) ? (result.dns.a as string[]).join(", ") : val(result.dns, "a")} />
                    )}
                    {result.dns.mx && (
                      <InfoRow label="MX Records" value={Array.isArray(result.dns.mx) ? (result.dns.mx as string[]).join(", ") : val(result.dns, "mx")} />
                    )}
                    {result.dns.ns && (
                      <InfoRow label="NS Records" value={Array.isArray(result.dns.ns) ? (result.dns.ns as string[]).join(", ") : val(result.dns, "ns")} />
                    )}
                    {entries(result.dns)
                      .filter(([k]) => !["a", "mx", "ns"].includes(k))
                      .map(([k, v]) => (
                        <InfoRow key={k} label={k} value={v} />
                      ))}
                  </>
                )}
                {!result.dns && (
                  <p className="text-[10px] text-gray-600 italic">No DNS data available</p>
                )}
              </div>
            </Card>

            {/* SSL Certificate Card */}
            <Card
              title="SSL Certificate"
              icon="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"
              delay={0.3}
            >
              {result.ssl_cert ? (
                <div className="space-y-0.5">
                  <InfoRow label="Issuer" value={val(result.ssl_cert, "issuer")} />
                  <InfoRow label="Subject" value={val(result.ssl_cert, "subject")} />
                  <InfoRow label="Valid From" value={val(result.ssl_cert, "not_before")} />
                  <InfoRow label="Valid Until" value={val(result.ssl_cert, "not_after")} />
                  {result.ssl_cert.days_remaining !== undefined && (
                    <div className="mt-2 flex items-center gap-2">
                      <span
                        className={`inline-block h-2 w-2 rounded-full ${
                          (result.ssl_cert.days_remaining as number) > 30
                            ? "bg-emerald-400"
                            : (result.ssl_cert.days_remaining as number) > 0
                              ? "bg-amber-400"
                              : "bg-red-500"
                        }`}
                      />
                      <span
                        className={`text-[11px] font-mono ${
                          (result.ssl_cert.days_remaining as number) > 30
                            ? "text-emerald-400"
                            : (result.ssl_cert.days_remaining as number) > 0
                              ? "text-amber-400"
                              : "text-red-400"
                        }`}
                      >
                        {result.ssl_cert.days_remaining as number} days remaining
                      </span>
                    </div>
                  )}
                  {entries(result.ssl_cert)
                    .filter(([k]) => !["issuer", "subject", "not_before", "not_after", "days_remaining"].includes(k))
                    .map(([k, v]) => (
                      <InfoRow key={k} label={k} value={v} />
                    ))}
                </div>
              ) : (
                <p className="text-[10px] text-gray-600 italic">No SSL certificate data</p>
              )}
            </Card>

            {/* Security Headers Card */}
            <Card
              title="Security Headers"
              icon="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z"
              delay={0.4}
            >
              <div className="space-y-2">
                {SECURITY_HEADERS.map(({ key, label }) => {
                  const headers = result.security_headers;
                  const present =
                    headers &&
                    (headers[key] !== undefined && headers[key] !== null && headers[key] !== false);
                  return (
                    <div key={key} className="flex items-center gap-2">
                      <span
                        className={`text-sm ${present ? "text-emerald-400" : "text-red-400"}`}
                      >
                        {present ? "\u2713" : "\u2717"}
                      </span>
                      <span className="text-[11px] text-gray-400">{label}</span>
                      {present && (
                        <span className="ml-auto max-w-[50%] truncate text-right text-[9px] font-mono text-gray-600">
                          {typeof headers![key] === "string"
                            ? (headers![key] as string).slice(0, 60)
                            : "present"}
                        </span>
                      )}
                    </div>
                  );
                })}
                {/* Additional security headers not in the standard list */}
                {result.security_headers &&
                  entries(result.security_headers)
                    .filter(([k]) => !SECURITY_HEADERS.some((h) => h.key === k))
                    .map(([k, v]) => (
                      <InfoRow key={k} label={k} value={v} />
                    ))}
              </div>
            </Card>

            {/* HTTP Info Card */}
            <Card
              title="HTTP Info"
              icon="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 9.75c0 .746-.092 1.472-.262 2.165"
              delay={0.5}
            >
              {result.http_headers ? (
                <div className="space-y-0.5">
                  {entries(result.http_headers).map(([k, v]) => (
                    <InfoRow key={k} label={k} value={v} />
                  ))}
                </div>
              ) : (
                <p className="text-[10px] text-gray-600 italic">No HTTP data available</p>
              )}
            </Card>

            {/* GeoIP Card */}
            <Card
              title="GeoIP Location"
              icon="M15 10.5a3 3 0 11-6 0 3 3 0 016 0z M19.5 10.5c0 7.142-7.5 11.25-7.5 11.25S4.5 17.642 4.5 10.5a7.5 7.5 0 1115 0z"
              delay={0.6}
            >
              {result.geo ? (
                <div className="space-y-0.5">
                  <InfoRow label="Country" value={val(result.geo, "country")} />
                  <InfoRow label="City" value={val(result.geo, "city")} />
                  <InfoRow label="Region" value={val(result.geo, "region")} />
                  <InfoRow label="Latitude" value={val(result.geo, "lat")} />
                  <InfoRow label="Longitude" value={val(result.geo, "lon")} />
                  {entries(result.geo)
                    .filter(([k]) => !["country", "city", "region", "lat", "lon"].includes(k))
                    .map(([k, v]) => (
                      <InfoRow key={k} label={k} value={v} />
                    ))}
                </div>
              ) : (
                <p className="text-[10px] text-gray-600 italic">No geolocation data</p>
              )}
            </Card>

            {/* WHOIS Card */}
            <Card
              title="WHOIS Info"
              icon="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m5.231 13.481L15 17.25m-4.5-15H5.625c-.621 0-1.125.504-1.125 1.125v16.5c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9zm3.75 11.625a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z"
              delay={0.7}
            >
              {result.whois_info ? (
                <div className="space-y-0.5">
                  <InfoRow label="Registrar" value={val(result.whois_info, "registrar")} />
                  <InfoRow label="Created" value={val(result.whois_info, "creation_date")} />
                  <InfoRow label="Expires" value={val(result.whois_info, "expiration_date")} />
                  <InfoRow label="Name Servers" value={val(result.whois_info, "name_servers")} />
                  {entries(result.whois_info)
                    .filter(([k]) => !["registrar", "creation_date", "expiration_date", "name_servers"].includes(k))
                    .map(([k, v]) => (
                      <InfoRow key={k} label={k} value={v} />
                    ))}
                </div>
              ) : (
                <p className="text-[10px] text-gray-600 italic">No WHOIS data available</p>
              )}
            </Card>
          </div>

          {/* Errors Card - only if errors */}
          {result.errors.length > 0 && (
            <Card
              title="Scan Errors"
              icon="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
              className="border-red-500/20"
              delay={0.8}
            >
              <div className="space-y-1.5">
                {result.errors.map((err, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 text-[11px] text-red-400"
                  >
                    <span className="mt-0.5 text-red-500">&#x25B2;</span>
                    <span className="font-mono">{err}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </>
      )}
    </PageTransition>
  );
}
