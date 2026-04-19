"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DataTable, type Column } from "@/components/DataTable";

interface Engagement {
  id: string;
  name: string;
  client_name: string;
  status: string;
}

interface Campaign {
  id: string;
  name: string;
  engagement_id: string | null;
  gophish_campaign_id: number | null;
  status: string;
  template_name: string;
  landing_url: string;
  sent_count: number;
  opened_count: number;
  clicked_count: number;
  submitted_count: number;
  email_failed_count: number;
  launched_at: string | null;
  completed_at: string | null;
  created_by: string | null;
  created_at: string;
  mitre_technique: string;
  notes: string;
  last_synced_at: string | null;
}

const STATUS_CLS: Record<string, string> = {
  draft: "border-gray-500/40 text-gray-300",
  sending: "border-blue-400/40 text-blue-300",
  "in-progress": "border-amber-400/40 text-amber-300",
  completed: "border-emerald-400/40 text-emerald-300",
  stopped: "border-orange-400/40 text-orange-300",
  failed: "border-red-400/40 text-red-300",
};

export default function PhishingCampaigns() {
  const router = useRouter();
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [statusInfo, setStatusInfo] = useState<{
    configured: boolean;
    detail?: string;
  } | null>(null);
  const [syncing, setSyncing] = useState<Record<string, boolean>>({});

  async function reload() {
    setLoading(true);
    setErr(null);
    try {
      const res = await fetch("/api/proxy/redteam/phishing/campaigns", {
        credentials: "include",
        cache: "no-store",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setCampaigns(Array.isArray(data) ? data : []);
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function loadStatus() {
    try {
      const res = await fetch("/api/proxy/redteam/phishing/status", {
        credentials: "include",
        cache: "no-store",
      });
      if (res.ok) {
        setStatusInfo({ configured: true });
      } else if (res.status === 503) {
        const body = await res.json().catch(() => ({}));
        setStatusInfo({
          configured: false,
          detail: body?.detail || "GoPhish not configured",
        });
      }
    } catch {
      setStatusInfo({ configured: false, detail: "GoPhish unreachable" });
    }
  }

  useEffect(() => {
    void reload();
    void loadStatus();
    fetch("/api/proxy/redteam/engagements", {
      credentials: "include",
      cache: "no-store",
    })
      .then((r) => (r.ok ? r.json() : []))
      .then((d) =>
        setEngagements(
          Array.isArray(d) ? d : Array.isArray(d?.items) ? d.items : [],
        ),
      )
      .catch(() => {});
  }, []);

  const engagementName = (id: string | null) => {
    if (!id) return "—";
    const e = engagements.find((x) => x.id === id);
    return e ? `${e.name} · ${e.client_name}` : id.slice(0, 8);
  };

  async function syncRow(id: string) {
    setSyncing((s) => ({ ...s, [id]: true }));
    try {
      await fetch(`/api/proxy/redteam/phishing/campaigns/${id}/sync`, {
        method: "POST",
        credentials: "include",
      });
      await reload();
    } finally {
      setSyncing((s) => ({ ...s, [id]: false }));
    }
  }

  const columns: Column<Campaign>[] = [
    {
      header: "NAME",
      accessor: (c) => (
        <span className="font-medium text-cyan-glow">{c.name}</span>
      ),
      sortValue: (c) => c.name,
    },
    {
      header: "ENGAGEMENT",
      accessor: (c) => (
        <span className="text-xs text-cyan-glow/70">
          {engagementName(c.engagement_id)}
        </span>
      ),
    },
    {
      header: "TEMPLATE",
      accessor: (c) => (
        <span className="text-xs text-cyan-glow/60">{c.template_name}</span>
      ),
    },
    {
      header: "STATUS",
      accessor: (c) => (
        <span
          className={`rounded border px-2 py-0.5 text-[10px] tracking-widest ${
            STATUS_CLS[c.status] ?? "border-cyan-glow/40 text-cyan-glow/80"
          }`}
        >
          {(c.status ?? "").toUpperCase()}
        </span>
      ),
      sortValue: (c) => c.status,
    },
    {
      header: "SENT",
      accessor: (c) => (
        <span className="font-mono text-cyan-glow/80">{c.sent_count}</span>
      ),
      sortValue: (c) => c.sent_count,
    },
    {
      header: "OPENED",
      accessor: (c) => (
        <span className="font-mono text-emerald-300/80">{c.opened_count}</span>
      ),
      sortValue: (c) => c.opened_count,
    },
    {
      header: "CLICKED",
      accessor: (c) => (
        <span className="font-mono text-amber-300/90">{c.clicked_count}</span>
      ),
      sortValue: (c) => c.clicked_count,
    },
    {
      header: "SUBMITTED",
      accessor: (c) => (
        <span className="font-mono text-red-400/90">{c.submitted_count}</span>
      ),
      sortValue: (c) => c.submitted_count,
    },
    {
      header: "LAUNCHED",
      accessor: (c) => (
        <span className="text-xs text-cyan-glow/60">
          {c.launched_at ? new Date(c.launched_at).toLocaleString() : "—"}
        </span>
      ),
      sortValue: (c) => c.launched_at ?? "",
    },
    {
      header: "ACTIONS",
      accessor: (c) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            void syncRow(c.id);
          }}
          disabled={syncing[c.id]}
          className="rounded border border-cyan-glow/40 px-2 py-0.5 text-[10px] tracking-widest text-cyan-glow hover:bg-cyan-glow/10 disabled:opacity-40"
        >
          {syncing[c.id] ? "SYNC..." : "SYNC"}
        </button>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-lg font-bold tracking-widest text-cyan-glow">
            PHISHING CAMPAIGNS
          </h1>
          <p className="text-[11px] tracking-wider text-cyan-glow/50">
            GOPHISH WORKFLOW // MITRE T1566.001 // PERSISTED + AUTO-SYNC
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => router.push("/redteam/phishing/new")}
            className="rounded border border-cyan-glow/40 bg-cyan-glow/10 px-3 py-1.5 text-xs tracking-widest text-cyan-glow hover:bg-cyan-glow/20"
          >
            + NEW CAMPAIGN
          </button>
        </div>
      </div>

      {statusInfo && !statusInfo.configured && (
        <div className="rounded-md border border-amber-400/30 bg-amber-500/10 p-3 text-xs text-amber-300">
          GoPhish not configured: {statusInfo.detail}. Set{" "}
          <code className="font-mono">GOPHISH_API_URL</code> and{" "}
          <code className="font-mono">GOPHISH_API_KEY</code> environment
          variables, then redeploy the API container.
        </div>
      )}

      <div className="rounded-md border border-cyan-glow/15 bg-space-dark/60">
        <DataTable<Campaign>
          columns={columns}
          data={campaigns}
          loading={loading}
          error={err}
          onRowClick={(c) => router.push(`/redteam/phishing/${c.id}`)}
        />
      </div>

      {!loading && campaigns.length === 0 && !err && (
        <div className="rounded-md border border-cyan-glow/15 bg-space-dark/40 p-6 text-center">
          <p className="text-sm text-cyan-glow/70">No campaigns yet.</p>
          <p className="mt-2 text-xs text-cyan-glow/50">
            Click <span className="text-cyan-glow">+ NEW CAMPAIGN</span> to
            launch your first GoPhish-backed assessment.
          </p>
        </div>
      )}
    </div>
  );
}
