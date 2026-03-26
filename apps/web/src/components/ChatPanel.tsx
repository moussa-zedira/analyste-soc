"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { sendChatMessage } from "@/lib/apiClient";
import type { ChatMessage } from "@/lib/types";

const QUICK_ACTIONS = [
  "Summarize today's threats",
  "Show brute force incidents",
  "Which IPs are most active?",
  "Any critical incidents open?",
];

export function ChatPanel() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState<string | undefined>();
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = useCallback(
    async (text?: string) => {
      const msg = (text ?? input).trim();
      if (!msg || loading) return;

      setInput("");
      setError(null);

      const userMsg: ChatMessage = {
        role: "user",
        content: msg,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, userMsg]);
      setLoading(true);

      try {
        const res = await sendChatMessage(msg, conversationId);
        setConversationId(res.conversation_id);
        const assistantMsg: ChatMessage = {
          role: "assistant",
          content: res.response,
          timestamp: new Date().toISOString(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Chat request failed");
      } finally {
        setLoading(false);
      }
    },
    [input, loading, conversationId],
  );

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <>
      {/* Toggle button */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="fixed bottom-5 right-5 z-50 flex h-12 w-12 items-center justify-center rounded-full border border-cyan-glow/30 bg-space-deep/90 text-cyan-glow shadow-cyan-md backdrop-blur-sm transition-all hover:bg-cyan-glow/10 hover:shadow-cyan-lg"
        title="SOC Assistant"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
          strokeWidth={1.5}
          stroke="currentColor"
          className="h-6 w-6"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M8.625 12a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H8.25m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H12m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 0 1-2.555-.337A5.972 5.972 0 0 1 5.41 20.97a5.969 5.969 0 0 1-.474-.065 4.48 4.48 0 0 0 .978-2.025c.09-.457-.133-.901-.467-1.226C3.93 16.178 3 14.189 3 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25Z"
          />
        </svg>
      </button>

      {/* Chat panel */}
      {open && (
        <div className="fixed bottom-20 right-5 z-50 flex h-[520px] w-96 flex-col glass-panel shadow-2xl shadow-cyan-glow/5 animate-slide-up">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-cyan-glow/10 px-4 py-3">
            <div>
              <h3 className="hud-heading text-xs font-bold tracking-widest text-cyan-glow">
                SOC Assistant
              </h3>
              <p className="text-[9px] tracking-wider text-cyan-glow/30">
                POWERED BY OLLAMA // LOCAL
              </p>
            </div>
            <button
              onClick={() => setOpen(false)}
              className="text-gray-600 transition-colors hover:text-cyan-glow"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="h-5 w-5"
                viewBox="0 0 20 20"
                fill="currentColor"
              >
                <path
                  fillRule="evenodd"
                  d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                  clipRule="evenodd"
                />
              </svg>
            </button>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
            {messages.length === 0 && (
              <div className="space-y-3">
                <p className="text-[10px] tracking-wider text-gray-600 text-center">
                  Ask me anything about your security data.
                </p>
                <div className="space-y-1.5">
                  {QUICK_ACTIONS.map((action) => (
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
              <div
                key={i}
                className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
              >
                <div
                  className={`max-w-[85%] rounded-md px-3 py-2 text-xs leading-relaxed ${
                    msg.role === "user"
                      ? "border border-cyan-glow/20 bg-cyan-glow/10 text-cyan-dim"
                      : "border border-gray-700/50 bg-space-mid/60 text-gray-300"
                  }`}
                >
                  <div className="whitespace-pre-wrap">{msg.content}</div>
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
                placeholder="Query security data..."
                className="flex-1 rounded-md border border-cyan-glow/15 bg-space-mid/50 px-3 py-2 text-xs text-gray-200 placeholder-gray-600 outline-none transition-colors focus:border-cyan-glow/40 focus:shadow-cyan-sm"
                disabled={loading}
              />
              <button
                onClick={() => handleSend()}
                disabled={loading || !input.trim()}
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
