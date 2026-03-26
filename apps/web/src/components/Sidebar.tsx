"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0a1 1 0 01-1-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 01-1 1" },
  { href: "/events", label: "Events", icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" },
  { href: "/incidents", label: "Incidents", icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" },
  { href: "/map", label: "Threat Map", icon: "M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l5.447 2.724A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" },
  { href: "/graph", label: "Graph", icon: "M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" },
  { href: "/mitre", label: "MITRE ATT&CK", icon: "M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" },
  { href: "/scanner", label: "Scanner", icon: "M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" },
];

/** Barre laterale de navigation principale avec logo et liens. */
export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="relative z-20 flex h-screen w-56 flex-col border-r border-cyan-glow/10 bg-space-dark/80 backdrop-blur-xl">
      {/* Top glow line */}
      <div className="absolute top-0 left-0 right-0 h-px bg-cyan-glow-line" />

      {/* Logo */}
      <div className="flex h-16 items-center border-b border-cyan-glow/10 px-4">
        <div className="flex items-center gap-3">
          {/* Hexagonal logo */}
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
            {/* Glow effect */}
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

      {/* Navigation */}
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

      {/* Footer */}
      <div className="border-t border-cyan-glow/10 p-3 space-y-2">
        {/* System status indicator */}
        <div className="flex items-center gap-2 px-3 py-2">
          <div className="relative">
            <div className="h-2 w-2 rounded-full bg-cyan-glow" />
            <div className="absolute inset-0 h-2 w-2 animate-ping rounded-full bg-cyan-glow opacity-40" />
          </div>
          <span className="text-[10px] tracking-wider text-cyan-glow/50">
            SYSTEM ONLINE
          </span>
        </div>
        <p className="px-3 text-[9px] tracking-wider text-cyan-glow/20">
          CYBERDEF v0.1 // SPATIAL UI
        </p>
      </div>

      {/* Right edge glow */}
      <div className="absolute top-0 right-0 bottom-0 w-px bg-gradient-to-b from-transparent via-cyan-glow/20 to-transparent" />
    </aside>
  );
}
