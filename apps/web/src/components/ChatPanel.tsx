"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { listEngagements, sendChatMessage } from "@/lib/apiClient";
import type { ChatMessage } from "@/lib/types";

type Engagement = {
  id: string;
  name: string;
  client_name: string;
  status: string;
  kill_switch_active: boolean;
};

type ChatMsgEx = ChatMessage & {
  provider?: string;
  model?: string;
  cost_usd?: number;
};

const SOC_QUICK = [
  "Resume des menaces du jour",
  "Incidents brute force recents",
  "IPs les plus actives",
  "Incidents critiques ouverts",
];

const PENTEST_QUICK = [
  "Prochaine etape vu l'etat du C2 ?",
  "Chemins d'attaque BloodHound prioritaires",
  "Techniques MITRE a tester sur le scope",
  "Analyse des creds recoltees",
];

const PROVIDERS: Array<{ key: "anthropic" | "openai" | "ollama"; label: string }> = [
  { key: "anthropic", label: "CLAUDE" },
  { key: "openai", label: "GPT" },
  { key: "ollama", label: "LOCAL" },
];

/** Assistant pentest / SOC avec contexte engagement. */
export function ChatPanel() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMsgEx[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState<string | undefined>();
  const [error, setError] = useState<string | null>(null);

  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engagementId, setEngagementId] = useState<string | undefined>(undefined);
  const [provider, setProvider] = useState<"anthropic" | "openai" | "ollama" | undefined>(undefined);
  const [lastProviderUsed, setLastProviderUsed] = useState<string | undefined>();
  const [hydrated, setHydrated] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Lit le localStorage cote client uniquement (evite hydration mismatch)
  useEffect(() => {
    try {
      const eng = localStorage.getItem("chat.engagement_id");
      if (eng) setEngagementId(eng);
      const prov = localStorage.getItem("chat.provider") as
        | "anthropic"
        | "openai"
        | "ollama"
        | null;
      if (prov) setProvider(prov);
    } catch {
      /* ignore */
    }
    setHydrated(true);
  }, []);

  useEffect(() => {
    if (!open) return;
    listEngagements()
      .then((arr) => setEngagements(Array.isArray(arr) ? arr : []))
      .catch(() => setEngagements([]));
  }, [open]);

  useEffect(() => {
    if (!hydrated) return;
    try {
      if (engagementId) localStorage.setItem("chat.engagement_id", engagementId);
      else localStorage.removeItem("chat.engagement_id");
    } catch {
      /* ignore */
    }
  }, [engagementId, hydrated]);

  useEffect(() => {
    if (!hydrated) return;
    try {
      if (provider) localStorage.setItem("chat.provider", provider);
      else localStorage.removeItem("chat.provider");
    } catch {
      /* ignore */
    }
  }, [provider, hydrated]);

  const activeEng = engagements.find((e) => e.id === engagementId);
  const quickActions = engagementId ? PENTEST_QUICK : SOC_QUICK;

  const handleSend = useCallback(
    async (text?: string) => {
      const msg = (text ?? input).trim();
      if (!msg || loading) return;

      setInput("");
      setError(null);

      const userMsg: ChatMsgEx = {
        role: "user",
        content: msg,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, userMsg]);
      setLoading(true);

      try {
        const res = await sendChatMessage(msg, conversationId, engagementId, provider);
        setConversationId(res.conversation_id);
        setLastProviderUsed(res.provider);
        const assistantMsg: ChatMsgEx = {
          role: "assistant",
          content: res.response,
          timestamp: new Date().toISOString(),
          provider: res.provider,
          model: res.model,
          cost_usd: res.cost_usd,
        };
        setMessages((prev) => [...prev, assistantMsg]);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Chat request failed");
      } finally {
        setLoading(false);
      }
    },
    [input, loading, conversationId, engagementId, provider],
  );

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleReset = () => {
    setMessages([]);
    setConversationId(undefined);
    setError(null);
  };

  return (
    <>
      {/* Toggle button */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="fixed bottom-5 right-5 z-50 flex h-12 w-12 items-center justify-center rounded-full border border-cyan-glow/30 bg-space-deep/90 text-cyan-glow shadow-cyan-md backdrop-blur-sm transition-all hover:bg-cyan-glow/10 hover:shadow-cyan-lg"
        title="Pentest Assistant"
      >
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-6 w-6">
          <path strokeLinecap="round" strokeLinejoin="round" d="M8.625 12a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H8.25m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H12m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 0 1-2.555-.337A5.972 5.972 0 0 1 5.41 20.97a5.969 5.969 0 0 1-.474-.065 4.48 4.48 0 0 0 .978-2.025c.09-.457-.133-.901-.467-1.226C3.93 16.178 3 14.189 3 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25Z" />
        </svg>
      </button>

      {/* Panel */}
      {open && (
        <div className="fixed bottom-20 right-5 z-50 flex h-[620px] w-[420px] flex-col glass-panel shadow-2xl shadow-cyan-glow/5 animate-slide-up">
          {/* Header */}
          <div className="border-b border-cyan-glow/10 px-4 py-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="hud-heading text-xs font-bold tracking-widest text-cyan-glow">
                  {engagementId ? "PENTEST ASSISTANT" : "SOC ASSISTANT"}
                </h3>
                <p className="text-[9px] tracking-wider text-cyan-glow/40">
                  {lastProviderUsed ? `VIA ${lastProviderUsed.toUpperCase()}` : "MULTI-PROVIDER"}
                  {activeEng && ` // ${activeEng.client_name.toUpperCase()}`}
                  {activeEng?.kill_switch_active && " // KILLED"}
                </p>
              </div>
              <div className="flex gap-2">
                <button onClick={handleReset} title="Nouvelle conversation" className="text-gray-600 transition-colors hover:text-cyan-glow">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clipRule="evenodd" />
                  </svg>
                </button>
                <button onClick={() => setOpen(false)} className="text-gray-600 transition-colors hover:text-cyan-glow">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                  </svg>
                </button>
              </div>
            </div>

            {/* Engagement + provider selectors */}
            <div className="mt-2 flex gap-2">
              <select
                value={engagementId ?? ""}
                onChange={(e) => {
                  setEngagementId(e.target.value || undefined);
                  handleReset();
                }}
                className="flex-1 rounded-md border border-cyan-glow/15 bg-space-mid/50 px-2 py-1 text-[10px] text-gray-300 outline-none focus:border-cyan-glow/40"
              >
                <option value="">— Mode SOC (sans engagement) —</option>
                {engagements.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.name} ({e.client_name}) {e.kill_switch_active ? "⛔" : ""}
                  </option>
                ))}
              </select>
              <select
                value={provider ?? ""}
                onChange={(e) =>
                  setProvider(
                    (e.target.value as "anthropic" | "openai" | "ollama") || undefined,
                  )
                }
                className="w-24 rounded-md border border-cyan-glow/15 bg-space-mid/50 px-2 py-1 text-[10px] text-gray-300 outline-none focus:border-cyan-glow/40"
              >
                <option value="">AUTO</option>
                {PROVIDERS.map((p) => (
                  <option key={p.key} value={p.key}>
                    {p.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
            {messages.length === 0 && (
              <div className="space-y-3">
                <p className="text-[10px] tracking-wider text-gray-600 text-center">
                  {engagementId
                    ? "Assistant pentest — scope + RoE auto-injectes."
                    : "Assistant SOC — selectionne un engagement pour le mode pentest."}
                </p>
                <div className="space-y-1.5">
                  {quickActions.map((action) => (
                    <button
                      key={action}
                      onClick={() => handleSend(action)}
                      className="block w-full rounded-md border border-cyan-glow/10 bg-space-mid/50 px-3 py-2 text-left text-[11px] text-gray-400 transition-all hover:border-cyan-glow/25 hover:bg-cyan-glow/5 hover:text-cyan-dim"
                    >
                      {action}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div
                  className={`max-w-[85%] rounded-md px-3 py-2 text-xs leading-relaxed ${
                    msg.role === "user"
                      ? "border border-cyan-glow/20 bg-cyan-glow/10 text-cyan-dim"
                      : "border border-gray-700/50 bg-space-mid/60 text-gray-300"
                  }`}
                >
                  <div className="whitespace-pre-wrap">{msg.content}</div>
                  {msg.role === "assistant" && msg.provider && (
                    <div className="mt-1 flex gap-2 text-[9px] tracking-wider text-gray-600">
                      <span>{msg.provider}</span>
                      {msg.model && <span>// {msg.model}</span>}
                      {typeof msg.cost_usd === "number" && msg.cost_usd > 0 && (
                        <span>// ${msg.cost_usd.toFixed(5)}</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex justify-start">
                <div className="rounded-md border border-cyan-glow/10 bg-space-mid/50 px-3 py-2 text-xs text-cyan-glow/50">
                  <span className="animate-pulse">Processing...</span>
                </div>
              </div>
            )}

            {error && (
              <div className="rounded-md border border-red-500/20 bg-red-500/5 px-3 py-2 text-xs text-red-400">
                {error}
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="border-t border-cyan-glow/10 px-4 py-3">
            <div className="flex gap-2">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={engagementId ? "Question pentest..." : "Question SOC..."}
                className="flex-1 rounded-md border border-cyan-glow/15 bg-space-mid/50 px-3 py-2 text-xs text-gray-200 placeholder-gray-600 outline-none transition-colors focus:border-cyan-glow/40 focus:shadow-cyan-sm"
                disabled={loading || activeEng?.kill_switch_active}
              />
              <button
                onClick={() => handleSend()}
                disabled={loading || !input.trim() || activeEng?.kill_switch_active}
                className="rounded-md border border-cyan-glow/20 bg-cyan-glow/10 px-3 py-2 text-[10px] font-bold tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 disabled:opacity-50"
              >
                SEND
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
