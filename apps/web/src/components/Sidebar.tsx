"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { usePathname, useRouter } from "next/navigation";
import { FavoritesSidebar } from "@/components/Favorites";
import { ThemeToggle } from "@/components/ThemeToggle";

const NAV_ITEMS = [
  // SIEM Core
  { href: "/", label: "Dashboard", icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0a1 1 0 01-1-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 01-1 1" },
  { href: "/search", label: "Search (CQL)", icon: "M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" },
  { href: "/events", label: "Events", icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" },
  { href: "/incidents", label: "Incidents", icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" },
  { href: "/sources", label: "Log Sources", icon: "M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3" },
  { href: "/hunting", label: "Threat Hunting", icon: "M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607zM10.5 7.5v6m3-3h-6" },
  { href: "/ioc", label: "IOC", icon: "M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75" },
  { href: "/threat-intel", label: "Threat Intel", icon: "M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z" },
  { href: "/alerts", label: "Alert Channels", icon: "M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" },

  // Red Team
  { href: "/redteam/console", label: "Operator Console", icon: "M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" },
  { href: "/redteam/phishing", label: "Phishing", icon: "M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" },
  { href: "/redteam/bloodhound", label: "BloodHound", icon: "M4.26 10.147a60.438 60.438 0 0 0-.491 6.347A48.62 48.62 0 0 1 12 20.904a48.62 48.62 0 0 1 8.232-4.41 60.46 60.46 0 0 0-.491-6.347m-15.482 0A50.717 50.717 0 0 1 12 13.489a50.702 50.702 0 0 1 7.74-3.342M6.75 15a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm0 0v-3.675A55.378 55.378 0 0 1 12 8.443" },
  { href: "/pentest/c2", label: "C2 (Sliver)", icon: "M9.348 14.651a3.75 3.75 0 010-5.303m5.304 0a3.75 3.75 0 010 5.303m-7.425 2.122a6.75 6.75 0 010-9.546m9.546 0a6.75 6.75 0 010 9.546" },

  // OSINT / Recon
  { href: "/recon", label: "OSINT Recon", icon: "M3.75 3A1.75 1.75 0 002 4.75v3.5C2 9.216 2.784 10 3.75 10h3.5A1.75 1.75 0 009 8.25v-3.5A1.75 1.75 0 007.25 3h-3.5zM14 4.75A1.75 1.75 0 0115.75 3h3.5c.966 0 1.75.784 1.75 1.75v3.5A1.75 1.75 0 0119.25 10h-3.5A1.75 1.75 0 0114 8.25v-3.5z" },
  { href: "/pentest/subdomain", label: "Sous-domaines", icon: "M12 21v-8.25M15.75 21v-8.25M8.25 21v-8.25M3 9l9-6 9 6m-1.5 12V10.332A48.36 48.36 0 0012 9.75c-2.551 0-5.056.2-7.5.582V21" },
  { href: "/pentest/crawler", label: "Web Crawler", icon: "M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3" },
  { href: "/pentest/netscan", label: "Net Scanner", icon: "M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 0a8.997 8.997 0 017.843 4.582" },

  // Pentest Web
  { href: "/pentest/pipeline", label: "Pipeline Auto", icon: "M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25H12" },
  { href: "/pentest/auto-exploit", label: "Auto-Exploit", icon: "M13 10V3L4 14h7v7l9-11h-7z" },
  { href: "/pentest/sqli", label: "SQLi Engine", icon: "M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375" },
  { href: "/pentest/xss-engine", label: "XSS Engine", icon: "M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" },
  { href: "/pentest/brute", label: "Brute Force", icon: "M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" },

  // IA
  { href: "/ai/triage", label: "AI Triage", icon: "M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" },
  { href: "/ai/rag", label: "RAG Search", icon: "M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607zM10.5 7.5v3m0 0v3m0-3h3m-3 0h-3" },
  { href: "/ai/rule-gen", label: "Auto Rule Gen", icon: "M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z" },

  // SOAR
  { href: "/soar/playbooks", label: "Playbooks", icon: "M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z" },
  { href: "/soar/executions", label: "Executions", icon: "M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z" },

  // Doc + Admin
  { href: "/pentest/docs", label: "Pentest Docs", icon: "M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" },
  { href: "/assets", label: "Asset Inventory", icon: "M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3" },
  { href: "/reports", label: "Reports", icon: "M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" },
  { href: "/admin", label: "Admin", icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z" },
];

/** Barre laterale de navigation principale avec logo et liens. */
export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();

  const handleLogout = async () => {
    try {
      const { useAuthStore } = await import("@/stores/authStore");
      await useAuthStore.getState().logout();
    } finally {
      router.replace("/login");
    }
  };

  return (
    <aside className="relative z-20 flex h-screen w-56 flex-col border-r border-cyan-glow/10 bg-space-dark/80 backdrop-blur-xl">
      <div className="absolute top-0 left-0 right-0 h-px bg-cyan-glow-line" />

      <div className="flex h-16 items-center border-b border-cyan-glow/10 px-4">
        <div className="flex items-center gap-3">
          <div className="relative flex h-9 w-9 items-center justify-center">
            <svg viewBox="0 0 36 36" className="h-9 w-9">
              <polygon
                points="18,2 32,10 32,26 18,34 4,26 4,10"
                fill="none"
                stroke="#00E5FF"
                strokeWidth="1.5"
                opacity="0.6"
              />
              <polygon
                points="18,6 28,12 28,24 18,30 8,24 8,12"
                fill="rgba(0, 229, 255, 0.08)"
                stroke="#00E5FF"
                strokeWidth="0.5"
                opacity="0.4"
              />
              <text
                x="18"
                y="21"
                textAnchor="middle"
                fill="#00E5FF"
                fontSize="12"
                fontFamily="Orbitron, sans-serif"
                fontWeight="700"
              >
                CD
              </text>
            </svg>
            <div className="absolute inset-0 rounded-full opacity-20 blur-md" style={{ background: "radial-gradient(circle, #00E5FF 0%, transparent 70%)" }} />
          </div>
          <div>
            <span className="hud-heading text-sm font-bold tracking-widest text-cyan-glow">
              CyberDef
            </span>
            <p className="text-[9px] tracking-wider text-cyan-glow/30">
              DEFENSE SYSTEM
            </p>
          </div>
        </div>
      </div>

      <FavoritesSidebar />

      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        <p className="hud-label mb-3 px-3">Navigation</p>
        {NAV_ITEMS.map((item, index) => {
          const active =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          return (
            <motion.div
              key={item.href}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 + index * 0.05, duration: 0.3, ease: "easeOut" }}
            >
              <Link
                href={item.href}
                className={`group flex items-center gap-2.5 rounded-md px-3 py-2 text-xs font-medium transition-all duration-200 ${
                  active
                    ? "border border-cyan-glow/20 bg-cyan-glow/10 text-cyan-glow shadow-cyan-sm"
                    : "border border-transparent text-gray-500 hover:border-cyan-glow/10 hover:bg-cyan-glow/5 hover:text-cyan-dim"
                }`}
              >
                <svg
                  className={`h-4 w-4 flex-shrink-0 transition-colors ${
                    active ? "text-cyan-glow" : "text-gray-600 group-hover:text-cyan-dim"
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  strokeWidth={1.5}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d={item.icon}
                  />
                </svg>
                {item.label}
              </Link>
            </motion.div>
          );
        })}
      </nav>

      <div className="border-t border-cyan-glow/10 p-3 space-y-2">
        <ThemeToggle />
        <div className="flex items-center gap-2 px-3 py-2">
          <div className="relative">
            <div className="h-2 w-2 rounded-full bg-cyan-glow" />
            <div className="absolute inset-0 h-2 w-2 animate-ping rounded-full bg-cyan-glow opacity-40" />
          </div>
          <span className="text-[10px] tracking-wider text-cyan-glow/50">
            SYSTEM ONLINE
          </span>
        </div>
        <Link
          href="/profile"
          className={`flex w-full items-center gap-2 rounded-md px-3 py-2 text-[10px] font-bold tracking-widest transition-all ${
            pathname === "/profile"
              ? "border border-cyan-glow/20 bg-cyan-glow/10 text-cyan-glow shadow-cyan-sm"
              : "text-gray-500 hover:bg-cyan-glow/5 hover:text-cyan-dim"
          }`}
        >
          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z" />
          </svg>
          PROFILE
        </Link>
        <button
          onClick={handleLogout}
          className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-[10px] font-bold tracking-widest text-red-400/70 transition-all hover:bg-red-500/10 hover:text-red-400"
        >
          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3-3h-9m9 0l-3-3m3 3l-3 3" />
          </svg>
          DECONNEXION
        </button>
        <p className="px-3 text-[9px] tracking-wider text-cyan-glow/20">
          CYBERDEF v0.1 // SPATIAL UI
        </p>
      </div>

      <div className="absolute top-0 right-0 bottom-0 w-px bg-gradient-to-b from-transparent via-cyan-glow/20 to-transparent" />
    </aside>
  );
}
