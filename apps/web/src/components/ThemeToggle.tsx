"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";

/* ------------------------------------------------------------------ */
/*  Theme definitions                                                  */
/* ------------------------------------------------------------------ */
type ThemeMode = "dark" | "light" | "midnight";

const THEMES: { mode: ThemeMode; label: string; description: string }[] = [
  { mode: "dark", label: "Space", description: "Default space theme" },
  { mode: "light", label: "Light", description: "Clean white interface" },
  { mode: "midnight", label: "Midnight", description: "Deep blue enhanced" },
];

const LS_KEY = "cyberdef_theme";

/* ------------------------------------------------------------------ */
/*  Icon components                                                    */
/* ------------------------------------------------------------------ */
function SunIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z" />
    </svg>
  );
}

function MoonIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" />
    </svg>
  );
}

function MidnightIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
    </svg>
  );
}

const ICONS: Record<ThemeMode, (props: { className?: string }) => React.ReactElement> = {
  dark: MoonIcon,
  light: SunIcon,
  midnight: MidnightIcon,
};

/* ------------------------------------------------------------------ */
/*  Apply theme class to <html>                                        */
/* ------------------------------------------------------------------ */
function applyTheme(mode: ThemeMode) {
  const root = document.documentElement;
  root.classList.remove("theme-dark", "theme-light", "theme-midnight");
  root.classList.add(`theme-${mode}`);

  // Tailwind darkMode: "class" -- light mode removes "dark"
  if (mode === "light") {
    root.classList.remove("dark");
  } else {
    root.classList.add("dark");
  }
}

/* ------------------------------------------------------------------ */
/*  ThemeToggle component                                              */
/* ------------------------------------------------------------------ */
export function ThemeToggle() {
  const [theme, setTheme] = useState<ThemeMode>("dark");
  const [open, setOpen] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const saved = localStorage.getItem(LS_KEY) as ThemeMode | null;
    const initial = saved && ["dark", "light", "midnight"].includes(saved) ? saved : "dark";
    setTheme(initial);
    applyTheme(initial);
  }, []);

  const selectTheme = useCallback((mode: ThemeMode) => {
    setTheme(mode);
    localStorage.setItem(LS_KEY, mode);
    applyTheme(mode);
    setOpen(false);
    window.dispatchEvent(new CustomEvent("theme-changed", { detail: mode }));
  }, []);

  // Cycle through themes on single click
  const cycle = useCallback(() => {
    const order: ThemeMode[] = ["dark", "light", "midnight"];
    const next = order[(order.indexOf(theme) + 1) % order.length];
    selectTheme(next);
  }, [theme, selectTheme]);

  if (!mounted) return null;

  const CurrentIcon = ICONS[theme];

  return (
    <div className="relative">
      <motion.button
        onClick={cycle}
        onContextMenu={(e) => { e.preventDefault(); setOpen((p) => !p); }}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.9 }}
        className="flex items-center gap-2 rounded-md px-3 py-2 text-[10px] font-bold tracking-widest transition-all duration-200 border border-transparent hover:border-cyan-glow/15 hover:bg-cyan-glow/5 w-full group"
        title={`Theme: ${THEMES.find((t) => t.mode === theme)?.label} (click to cycle, right-click for menu)`}
      >
        <motion.div
          key={theme}
          initial={{ rotate: -90, scale: 0.5, opacity: 0 }}
          animate={{ rotate: 0, scale: 1, opacity: 1 }}
          transition={{ type: "spring", stiffness: 400, damping: 15 }}
        >
          <CurrentIcon className="h-4 w-4 text-cyan-glow/70 group-hover:text-cyan-glow transition-colors" />
        </motion.div>
        <span className="text-cyan-glow/50 group-hover:text-cyan-glow/80 tracking-wider uppercase transition-colors">
          {THEMES.find((t) => t.mode === theme)?.label}
        </span>
      </motion.button>

      {/* Dropdown (right-click) */}
      <AnimatePresence>
        {open && (
          <>
            <motion.div
              className="fixed inset-0 z-40"
              onClick={() => setOpen(false)}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            />
            <motion.div
              initial={{ opacity: 0, y: 4, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 4, scale: 0.95 }}
              transition={{ duration: 0.15 }}
              className="absolute bottom-full left-0 mb-2 z-50 w-48 rounded-md border border-cyan-glow/15 bg-space-dark/95 backdrop-blur-xl shadow-cyan-lg overflow-hidden"
            >
              <div className="p-1">
                {THEMES.map((t) => {
                  const Icon = ICONS[t.mode];
                  const active = theme === t.mode;
                  return (
                    <button
                      key={t.mode}
                      onClick={() => selectTheme(t.mode)}
                      className={`flex w-full items-center gap-2.5 rounded px-3 py-2 text-[10px] font-medium transition-all duration-150 ${
                        active
                          ? "bg-cyan-glow/10 text-cyan-glow"
                          : "text-gray-500 hover:bg-cyan-glow/5 hover:text-cyan-dim"
                      }`}
                    >
                      <Icon className={`h-3.5 w-3.5 ${active ? "text-cyan-glow" : "text-gray-600"}`} />
                      <div className="text-left">
                        <div className="tracking-wider uppercase">{t.label}</div>
                        <div className="text-[8px] text-cyan-glow/30 tracking-wide">{t.description}</div>
                      </div>
                      {active && (
                        <motion.div
                          layoutId="theme-check"
                          className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-glow shadow-cyan-sm"
                        />
                      )}
                    </button>
                  );
                })}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
