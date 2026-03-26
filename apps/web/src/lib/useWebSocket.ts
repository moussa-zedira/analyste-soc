"use client";

import { useEffect, useRef, useState } from "react";

export interface WsMessage {
  type: "new_event" | "new_incident";
  payload: Record<string, unknown>;
}

interface UseWebSocketOptions {
  onMessage?: (msg: WsMessage) => void;
  enabled?: boolean;
}

/** Hook de connexion WebSocket pour recevoir les evenements et incidents en temps reel. */
export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { onMessage, enabled = true } = options;
  const [connected, setConnected] = useState(false);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    if (!enabled) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl =
      process.env.NEXT_PUBLIC_WS_URL ??
      `${protocol}//${window.location.hostname}:8000/ws/live`;

    let ws: WebSocket;
    let reconnectTimer: ReturnType<typeof setTimeout>;
    let disposed = false;

    function connect() {
      if (disposed) return;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!disposed) {
          reconnectTimer = setTimeout(connect, 3000);
        }
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data);
          onMessageRef.current?.(msg);
        } catch {
          /* ignore malformed messages */
        }
      };
    }

    connect();

    return () => {
      disposed = true;
      clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [enabled]);

  return { connected };
}
