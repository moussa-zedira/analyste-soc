"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import Modal from "./Modal";

/* ------------------------------------------------------------------ */
/*  Shortcut definitions                                               */
/* ------------------------------------------------------------------ */
interface Shortcut {
  keys: string[];
  label: string;
  category: "Navigation" | "Actions" | "General";
}

const SHORTCUTS: Shortcut[] = [
  { keys: ["Ctrl", "K"], label: "Command Palette", category: "General" },
  { keys: ["?"], label: "Keyboard shortcuts", category: "General" },
  { keys: ["Esc"], label: "Close modal / panel", category: "General" },
  { keys: ["G", "D"], label: "Go to Dashboard", category: "Navigation" },
  { keys: ["G", "E"], label: "Go to Events", category: "Navigation" },
  { keys: ["G", "I"], label: "Go to Incidents", category: "Navigation" },
  { keys: ["G", "M"], label: "Go to Map", category: "Navigation" },
  { keys: ["G", "P"], label: "Go to Pentest", category: "Navigation" },
  { keys: ["N"], label: "Toggle notifications", category: "Actions" },
  { keys: ["L"], label: "Toggle live feed", category: "Actions" },
];

const NAV_MAP: Record<string, string> = {
  d: "/",
  e: "/events",
  i: "/incidents",
  m: "/map",
  p: "/pentest",
};

/* ------------------------------------------------------------------ */
/*  Key badge component                                                */
/* ------------------------------------------------------------------ */
function Kbd({ children }: { children: string }) {
  return (
    <kbd className="inline-flex items-center justify-center min-w-[1.6rem] h-6 px-1.5 rounded border border-cyan-glow/20 bg-space-mid/60 text-[0.65rem] font-['Orbitron'] font-semibold uppercase tracking-wider text-cyan-glow shadow-[0_0_4px_rgba(0,229,255,0.15)] select-none">
      {children}
    </kbd>
  );
}

/* ------------------------------------------------------------------ */
/*  KeyboardShortcuts component                                        */
/* ------------------------------------------------------------------ */
export default function KeyboardShortcuts() {
  const router = useRouter();
  const [helpOpen, setHelpOpen] = useState(false);
  const pendingPrefix = useRef<string | null>(null);
  const prefixTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearPrefix = useCallback(() => {
    pendingPrefix.current = null;
    if (prefixTimer.current) {
      clearTimeout(prefixTimer.current);
      prefixTimer.current = null;
    }
  }, []);

  useEffect(() => {
    function isInputFocused() {
      const el = document.activeElement;
      if (!el) return false;
      const tag = el.tagName.toLowerCase();
      return (
        tag === "input" ||
        tag === "textarea" ||
        tag === "select" ||
        (el as HTMLElement).isContentEditable
      );
    }

    function onKeyDown(e: KeyboardEvent) {
      // Skip if user is typing in a form field (except Escape)
      if (isInputFocused() && e.key !== "Escape") return;

      // Ctrl+K: command palette hook point
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        return;
      }

      // Escape: close help modal
      if (e.key === "Escape") {
        if (helpOpen) setHelpOpen(false);
        clearPrefix();
        return;
      }

      // ?: toggle shortcuts help
      if (e.key === "?" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        setHelpOpen((prev) => !prev);
        clearPrefix();
        return;
      }

      // Two-key sequences: G then <key>
      if (pendingPrefix.current === "g") {
        const target = NAV_MAP[e.key.toLowerCase()];
        if (target) {
          e.preventDefault();
          router.push(target);
        }
        clearPrefix();
        return;
      }

      // Start G prefix
      if (
        e.key.toLowerCase() === "g" &&
        !e.ctrlKey &&
        !e.metaKey &&
        !e.altKey
      ) {
        pendingPrefix.current = "g";
        prefixTimer.current = setTimeout(clearPrefix, 800);
        return;
      }

      // N: toggle notifications
      if (
        e.key.toLowerCase() === "n" &&
        !e.ctrlKey &&
        !e.metaKey &&
        !e.altKey
      ) {
        window.dispatchEvent(new CustomEvent("toggle-notifications"));
        return;
      }

      // L: toggle live feed
      if (
        e.key.toLowerCase() === "l" &&
        !e.ctrlKey &&
        !e.metaKey &&
        !e.altKey
      ) {
        window.dispatchEvent(new CustomEvent("toggle-livefeed"));
        return;
      }
    }

    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [helpOpen, router, clearPrefix]);

  /* Group shortcuts by category */
  const categories = ["General", "Navigation", "Actions"] as const;
  const grouped = Object.fromEntries(
    categories.map((cat) => [
      cat,
      SHORTCUTS.filter((s) => s.category === cat),
    ]),
  );

  return (
    <Modal
      isOpen={helpOpen}
      onClose={() => setHelpOpen(false)}
      title="Keyboard Shortcuts"
      size="md"
    >
      <div className="space-y-5">
        {categories.map((cat) => (
          <div key={cat}>
            <h3 className="hud-label mb-2.5 text-cyan-glow/50">{cat}</h3>
            <div className="space-y-1.5">
              {grouped[cat].map((shortcut) => (
                <div
                  key={shortcut.label}
                  className="flex items-center justify-between rounded px-3 py-2 bg-space-deep/40 border border-cyan-faint/20 hover:border-cyan-glow/20 transition-colors duration-150"
                >
                  <span className="text-[0.75rem] text-[#c8e6f0]/80">
                    {shortcut.label}
                  </span>
                  <span className="flex items-center gap-1">
                    {shortcut.keys.map((k, i) => (
                      <span key={i} className="flex items-center gap-1">
                        {i > 0 && (
                          <span className="text-[0.55rem] text-cyan-dim/40 mx-0.5">
                            then
                          </span>
                        )}
                        <Kbd>{k}</Kbd>
                      </span>
                    ))}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      <p className="mt-4 text-[0.6rem] text-cyan-dim/30 text-center tracking-wide uppercase font-['Orbitron']">
        Press <Kbd>?</Kbd> to toggle this panel
      </p>
    </Modal>
  );
}
