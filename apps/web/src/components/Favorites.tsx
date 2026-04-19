"use client";

import { useState, useEffect, useCallback } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { motion, AnimatePresence, Reorder } from "framer-motion";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */
interface FavoriteItem {
  href: string;
  label: string;
  icon: string;
}

const LS_KEY = "cyberdef_favorites";
const MAX_FAVORITES = 10;

/* ------------------------------------------------------------------ */
/*  Route label + icon lookup (mirrors Sidebar NAV_ITEMS)              */
/* ------------------------------------------------------------------ */
const ROUTE_META: Record<string, { label: string; icon: string }> = {
  "/": { label: "Dashboard", icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0a1 1 0 01-1-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 01-1 1" },
  "/events": { label: "Events", icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" },
  "/incidents": { label: "Incidents", icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" },
  "/map": { label: "Threat Map", icon: "M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l5.447 2.724A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" },
  "/graph": { label: "Graph", icon: "M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" },
  "/mitre": { label: "MITRE ATT&CK", icon: "M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" },
  "/sources": { label: "Log Sources", icon: "M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3" },
  "/investigate": { label: "Investigation", icon: "M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m5.231 13.481L15 17.25m-4.5-15H5.625c-.621 0-1.125.504-1.125 1.125v16.5c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9zm3.75 11.625a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" },
  "/threat-intel": { label: "Threat Intel", icon: "M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z" },
  "/recon": { label: "OSINT Recon", icon: "M3.75 3A1.75 1.75 0 002 4.75v3.5C2 9.216 2.784 10 3.75 10h3.5A1.75 1.75 0 009 8.25v-3.5A1.75 1.75 0 007.25 3h-3.5z" },
  "/scanner": { label: "Scanner", icon: "M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" },
  "/pentest": { label: "Pentest Lab", icon: "M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" },
  "/pentest/deep": { label: "Scan Profond", icon: "M12 2a10 10 0 1010 10A10 10 0 0012 2z" },
  "/pentest/pipeline": { label: "Pipeline Auto", icon: "M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25H12" },
  "/pentest/history": { label: "Scan History", icon: "M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" },
  "/admin": { label: "Admin", icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35" },
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */
function loadFavorites(): FavoriteItem[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(LS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveFavorites(items: FavoriteItem[]) {
  localStorage.setItem(LS_KEY, JSON.stringify(items));
}

function getPageMeta(pathname: string): { label: string; icon: string } {
  if (ROUTE_META[pathname]) return ROUTE_META[pathname];
  // Fallback: build label from last segment
  const segments = pathname.split("/").filter(Boolean);
  const last = segments[segments.length - 1] || "Page";
  const label = last.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  return {
    label,
    icon: "M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.563.563 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.562.562 0 00-.182-.557l-4.204-3.602a.563.563 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z",
  };
}

/* ------------------------------------------------------------------ */
/*  Star button (for breadcrumb area / top bar)                        */
/* ------------------------------------------------------------------ */
export function FavoriteStarButton() {
  const pathname = usePathname();
  const [favorites, setFavorites] = useState<FavoriteItem[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    setFavorites(loadFavorites());
  }, []);

  const isFav = favorites.some((f) => f.href === pathname);

  const toggle = useCallback(() => {
    setFavorites((prev) => {
      let next: FavoriteItem[];
      if (prev.some((f) => f.href === pathname)) {
        next = prev.filter((f) => f.href !== pathname);
      } else {
        if (prev.length >= MAX_FAVORITES) return prev; // max reached
        const meta = getPageMeta(pathname);
        next = [...prev, { href: pathname, label: meta.label, icon: meta.icon }];
      }
      saveFavorites(next);
      return next;
    });
  }, [pathname]);

  if (!mounted) return null;

  return (
    <motion.button
      onClick={toggle}
      whileTap={{ scale: 0.8 }}
      className="group relative flex items-center justify-center w-7 h-7 rounded-md border border-transparent hover:border-cyan-glow/20 hover:bg-cyan-glow/5 transition-all duration-200"
      title={isFav ? "Remove from favorites" : "Add to favorites"}
    >
      <motion.svg
        key={isFav ? "filled" : "empty"}
        initial={{ scale: 0.5, rotate: -30 }}
        animate={{ scale: 1, rotate: 0 }}
        transition={{ type: "spring", stiffness: 500, damping: 15 }}
        className={`h-4 w-4 transition-colors duration-200 ${
          isFav
            ? "text-yellow-400 drop-shadow-[0_0_6px_rgba(250,204,21,0.5)]"
            : "text-gray-600 group-hover:text-cyan-dim"
        }`}
        viewBox="0 0 24 24"
        fill={isFav ? "currentColor" : "none"}
        stroke="currentColor"
        strokeWidth={1.5}
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.563.563 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.562.562 0 00-.182-.557l-4.204-3.602a.563.563 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z"
        />
      </motion.svg>
      {/* Glow ring on filled */}
      {isFav && (
        <motion.div
          initial={{ scale: 0, opacity: 0.8 }}
          animate={{ scale: 1.8, opacity: 0 }}
          transition={{ duration: 0.5 }}
          className="absolute inset-0 rounded-full border border-yellow-400/40"
        />
      )}
    </motion.button>
  );
}

/* ------------------------------------------------------------------ */
/*  Sidebar favorites section                                          */
/* ------------------------------------------------------------------ */
export function FavoritesSidebar() {
  const pathname = usePathname();
  const [favorites, setFavorites] = useState<FavoriteItem[]>([]);
  const [collapsed, setCollapsed] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    setFavorites(loadFavorites());

    // Listen for storage changes from other tabs / the star button
    const onStorage = () => setFavorites(loadFavorites());
    window.addEventListener("storage", onStorage);

    // Custom event for same-tab sync
    const onFavChange = () => setFavorites(loadFavorites());
    window.addEventListener("favorites-changed", onFavChange);

    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("favorites-changed", onFavChange);
    };
  }, []);

  // Re-sync every time pathname changes (the star button may have toggled)
  useEffect(() => {
    setFavorites(loadFavorites());
  }, [pathname]);

  const removeFav = useCallback((href: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setFavorites((prev) => {
      const next = prev.filter((f) => f.href !== href);
      saveFavorites(next);
      window.dispatchEvent(new CustomEvent("favorites-changed"));
      return next;
    });
  }, []);

  const handleReorder = useCallback((newOrder: FavoriteItem[]) => {
    setFavorites(newOrder);
    saveFavorites(newOrder);
  }, []);

  if (!mounted) return null;

  return (
    <div className="px-3 mb-2">
      {/* Header */}
      <button
        onClick={() => setCollapsed((p) => !p)}
        className="flex w-full items-center gap-2 px-3 py-1.5 mb-1 text-left group"
      >
        <svg
          className="h-3.5 w-3.5 text-yellow-400/70 group-hover:text-yellow-400 transition-colors"
          viewBox="0 0 24 24"
          fill="currentColor"
          stroke="none"
        >
          <path d="M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.563.563 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.562.562 0 00-.182-.557l-4.204-3.602a.563.563 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z" />
        </svg>
        <span className="hud-label flex-1">Favorites</span>
        <motion.svg
          animate={{ rotate: collapsed ? -90 : 0 }}
          transition={{ duration: 0.2 }}
          className="h-3 w-3 text-cyan-glow/40"
          viewBox="0 0 20 20"
          fill="currentColor"
        >
          <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
        </motion.svg>
      </button>

      <AnimatePresence>
        {!collapsed && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            {/* Glass sub-panel */}
            <div className="rounded-md border border-cyan-glow/8 bg-gradient-to-b from-cyan-glow/[0.03] to-transparent backdrop-blur-sm p-1.5">
              {favorites.length === 0 ? (
                <p className="px-2 py-3 text-center text-[10px] text-cyan-glow/30 tracking-wide">
                  Star pages to add them here
                </p>
              ) : (
                <Reorder.Group
                  axis="y"
                  values={favorites}
                  onReorder={handleReorder}
                  className="space-y-0.5"
                >
                  {favorites.map((fav, idx) => {
                    const active = pathname === fav.href;
                    return (
                      <Reorder.Item
                        key={fav.href}
                        value={fav}
                        className="list-none"
                        whileDrag={{ scale: 1.02, zIndex: 50, boxShadow: "0 0 12px rgba(0,229,255,0.2)" }}
                      >
                        <Link
                          href={fav.href}
                          className={`group/fav flex items-center gap-2 rounded px-2 py-1.5 text-[10px] font-medium transition-all duration-150 cursor-grab active:cursor-grabbing ${
                            active
                              ? "bg-cyan-glow/10 text-cyan-glow border border-cyan-glow/20"
                              : "text-gray-500 hover:text-cyan-dim hover:bg-cyan-glow/5 border border-transparent"
                          }`}
                        >
                          <svg
                            className={`h-3 w-3 flex-shrink-0 ${active ? "text-cyan-glow" : "text-gray-600 group-hover/fav:text-cyan-dim"}`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                            strokeWidth={1.5}
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" d={fav.icon} />
                          </svg>
                          <span className="flex-1 truncate">{fav.label}</span>
                          {/* Remove button on hover */}
                          <motion.button
                            onClick={(e) => removeFav(fav.href, e)}
                            whileHover={{ scale: 1.2 }}
                            whileTap={{ scale: 0.8 }}
                            className="opacity-0 group-hover/fav:opacity-100 flex-shrink-0 p-0.5 rounded hover:bg-red-500/20 hover:text-red-400 text-gray-600 transition-all duration-150"
                            title="Remove"
                          >
                            <svg className="h-2.5 w-2.5" viewBox="0 0 20 20" fill="currentColor">
                              <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
                            </svg>
                          </motion.button>
                        </Link>
                      </Reorder.Item>
                    );
                  })}
                </Reorder.Group>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
