"use client";

import { usePathname } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";

/* ------------------------------------------------------------------ */
/*  Route label mapping                                                */
/* ------------------------------------------------------------------ */
const ROUTE_LABELS: Record<string, string> = {
  "": "Dashboard",
  events: "Events",
  incidents: "Incidents",
  map: "Threat Map",
  graph: "Graph",
  mitre: "MITRE ATT&CK",
  sources: "Log Sources",
  investigate: "Investigation",
  "threat-intel": "Threat Intel",
  recon: "Recon",
  scanner: "Scanner",
  pentest: "Pentest Lab",
  deep: "Scan Profond",
  pipeline: "Pipeline Auto",
  history: "Scan History",
  docs: "Pentest Docs",
  sessions: "Sessions",
  nvd: "CVE Search",
  hash: "Hash Cracker",
  report: "Rapport Pro",
  wordgen: "Wordlist Gen",
  blind: "Blind Extract",
  oob: "OOB Callback",
  ssrf: "SSRF Avance",
  subdomain: "Sous-domaines",
  "waf-bypass": "WAF Bypass",
  exfil: "Exfiltration",
  persist: "Persistence",
  antiforensics: "Anti-Forensics",
  killchain: "Kill Chain",
  shell: "Shell Handler",
  chain: "Attack Chain",
  sqli: "SQLi Engine",
  "xss-engine": "XSS Engine",
  "lfi-rce": "LFI > RCE",
  privesc: "Privesc",
  creds: "Cred Harvester",
  lateral: "Lateral Move",
  protocols: "Protocols",
  bridge: "Exec Bridge",
  c2: "C2 Server",
  proxy: "HTTP Proxy",
  evasion: "AV Evasion",
  fuzzer: "Fuzzer",
  "exploit-dev": "Exploit Dev",
  workflows: "Workflows",
  live: "Live Dashboard",
  "auto-exploit": "Auto-Exploit",
  headless: "Headless Scanner",
  stealth: "Stealth Ops",
  "net-evasion": "Network Evasion",
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */
function labelFor(segment: string): string {
  if (/^\d+$/.test(segment)) return `#${segment}`;
  if (/^[0-9a-f-]{36}$/i.test(segment)) return `#${segment.slice(0, 8)}`;
  return (
    ROUTE_LABELS[segment] ??
    segment
      .replace(/-/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase())
  );
}

/* ------------------------------------------------------------------ */
/*  Home icon                                                          */
/* ------------------------------------------------------------------ */
function HomeIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 20 20"
      fill="currentColor"
      className="h-3.5 w-3.5"
    >
      <path
        fillRule="evenodd"
        d="M9.293 2.293a1 1 0 011.414 0l7 7A1 1 0 0117 11h-1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-3a1 1 0 00-1-1H9a1 1 0 00-1 1v3a1 1 0 01-1 1H5a1 1 0 01-1-1v-6H3a1 1 0 01-.707-1.707l7-7z"
        clipRule="evenodd"
      />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Chevron separator                                                  */
/* ------------------------------------------------------------------ */
function Chevron() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 20 20"
      fill="currentColor"
      className="h-3 w-3 text-cyan-glow/50 mx-1.5 flex-shrink-0"
    >
      <path
        fillRule="evenodd"
        d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z"
        clipRule="evenodd"
      />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/*  Breadcrumbs component                                              */
/* ------------------------------------------------------------------ */
export default function Breadcrumbs() {
  const pathname = usePathname();

  const segments = pathname.split("/").filter(Boolean);

  const crumbs = segments.map((seg, i) => ({
    label: labelFor(seg),
    href: "/" + segments.slice(0, i + 1).join("/"),
    isCurrent: i === segments.length - 1,
  }));

  // Don't render on root dashboard
  if (segments.length === 0) return null;

  return (
    <motion.nav
      aria-label="Breadcrumb"
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
      className="flex items-center gap-0 text-[0.65rem] font-medium tracking-wide select-none"
    >
      {/* Home */}
      <Link
        href="/"
        className="flex items-center text-cyan-dim/70 hover:text-cyan-glow transition-colors duration-200"
        aria-label="Dashboard"
      >
        <HomeIcon />
      </Link>

      {crumbs.map((crumb, i) => (
        <motion.span
          key={crumb.href}
          className="flex items-center"
          initial={{ opacity: 0, x: -6 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.25, delay: 0.06 * (i + 1) }}
        >
          <Chevron />

          {crumb.isCurrent ? (
            <span className="font-['Orbitron'] text-[0.6rem] font-semibold uppercase tracking-[0.12em] text-cyan-glow drop-shadow-[0_0_4px_rgba(0,229,255,0.4)]">
              {crumb.label}
            </span>
          ) : (
            <Link
              href={crumb.href}
              className="font-['Orbitron'] text-[0.6rem] font-medium uppercase tracking-[0.1em] text-cyan-dim/60 hover:text-cyan-glow transition-colors duration-200"
            >
              {crumb.label}
            </Link>
          )}
        </motion.span>
      ))}
    </motion.nav>
  );
}
