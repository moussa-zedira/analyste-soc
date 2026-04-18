"use client";

import { useEffect, useState } from "react";

interface Engagement {
  id: string;
  name: string;
  client_name: string;
  status: string;
}

interface Props {
  selectedId: string | null;
  onChange: (id: string | null) => void;
}

export default function EngagementSelector({ selectedId, onChange }: Props) {
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setErr(null);
      try {
        const res = await fetch(
          "/api/proxy/redteam/engagements?status=active",
          { credentials: "include", cache: "no-store" },
        );
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        const data = await res.json();
        if (cancelled) return;
        const list = Array.isArray(data)
          ? data
          : Array.isArray(data?.items)
            ? data.items
            : [];
        setEngagements(list);
        if (!selectedId && list.length > 0) {
          onChange(list[0].id);
        }
      } catch (e) {
        if (!cancelled) setErr(String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] tracking-widest text-cyan-glow/50">
        ENGAGEMENT
      </span>
      <select
        value={selectedId ?? ""}
        onChange={(e) => onChange(e.target.value || null)}
        className="rounded border border-cyan-glow/20 bg-space-dark/80 px-2 py-1 text-xs text-cyan-glow focus:border-cyan-glow/60 focus:outline-none"
      >
        <option value="">— select —</option>
        {engagements.map((e) => (
          <option key={e.id} value={e.id}>
            {e.name} · {e.client_name}
          </option>
        ))}
      </select>
      {loading && (
        <span className="text-[10px] text-cyan-glow/40">loading...</span>
      )}
      {err && (
        <span className="text-[10px] text-red-400/70" title={err}>
          err
        </span>
      )}
    </div>
  );
}
