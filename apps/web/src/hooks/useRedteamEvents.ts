"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface RedteamEvent {
  type: string;
  data?: Record<string, unknown>;
  ts?: string;
}

export interface UseRedteamEventsResult {
  events: RedteamEvent[];
  status: "idle" | "connecting" | "open" | "closed" | "error";
  lastError: string | null;
  clear: () => void;
}

const MAX_BUFFER = 200;

/**
 * Connexion WebSocket vers ``/ws/redteam/c2/events``. Recupere d'abord
 * un JWT short-lived via ``/api/auth/ws-token`` (cookie HttpOnly cote
 * server), puis ouvre la WS sur le backend FastAPI direct (le proxy
 * Next ne sait pas upgrader vers WebSocket).
 *
 * - Filtre les heartbeats ``{type:"ping"}``
 * - Garde un buffer rolling de 200 events max
 * - Reconnecte automatiquement avec backoff exponentiel borne
 */
export function useRedteamEvents(): UseRedteamEventsResult {
  const [events, setEvents] = useState<RedteamEvent[]>([]);
  const [status, setStatus] = useState<UseRedteamEventsResult["status"]>("idle");
  const [lastError, setLastError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(0);
  const stoppedRef = useRef(false);

  const clear = useCallback(() => setEvents([]), []);

  useEffect(() => {
    stoppedRef.current = false;

    async function fetchToken(): Promise<string | null> {
      try {
        const res = await fetch("/api/auth/ws-token", {
          credentials: "include",
          cache: "no-store",
        });
        if (!res.ok) return null;
        const j = await res.json();
        return typeof j?.token === "string" ? j.token : null;
      } catch {
        return null;
      }
    }

    function wsBaseUrl(): string {
      const env =
        (process.env.NEXT_PUBLIC_API_BASE_URL as string | undefined) ?? "";
      if (env) return env.replace(/^http/, "ws");
      // Sinon, on cible le meme host en remplacant le port web par 8000.
      if (typeof window !== "undefined") {
        const proto = window.location.protocol === "https:" ? "wss" : "ws";
        return `${proto}://${window.location.hostname}:8000`;
      }
      return "ws://localhost:8000";
    }

    async function connect() {
      if (stoppedRef.current) return;
      setStatus("connecting");
      const token = await fetchToken();
      if (!token) {
        setStatus("error");
        setLastError("no auth token");
        scheduleReconnect();
        return;
      }
      const url =
        wsBaseUrl() +
        "/ws/redteam/c2/events?token=" +
        encodeURIComponent(token);
      let ws: WebSocket;
      try {
        ws = new WebSocket(url);
      } catch (e) {
        setStatus("error");
        setLastError(String(e));
        scheduleReconnect();
        return;
      }
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus("open");
        setLastError(null);
        retryRef.current = 0;
      };
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as RedteamEvent;
          if (msg?.type === "ping") return;
          setEvents((prev) => [msg, ...prev].slice(0, MAX_BUFFER));
        } catch {
          // payload non-JSON — ignore
        }
      };
      ws.onerror = () => {
        setStatus("error");
        setLastError("websocket error");
      };
      ws.onclose = () => {
        wsRef.current = null;
        setStatus("closed");
        scheduleReconnect();
      };
    }

    function scheduleReconnect() {
      if (stoppedRef.current) return;
      const attempt = retryRef.current + 1;
      retryRef.current = attempt;
      const delay = Math.min(30000, 1000 * Math.pow(2, Math.min(attempt, 5)));
      setTimeout(connect, delay);
    }

    void connect();

    return () => {
      stoppedRef.current = true;
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch {
          // ignore
        }
        wsRef.current = null;
      }
    };
  }, []);

  return { events, status, lastError, clear };
}
