"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

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
  mitre_technique: string;
  notes: string;
  last_synced_at: string | null;
}

interface Target {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  position: string;
  group_name: string;
  last_status: string;
  opened_at: string | null;
  clicked_at: string | null;
  submitted_at: string | null;
}

interface ResultEvent {
  id: string;
  target_id: string | null;
  event_type: string;
  ip_address: string;
  user_agent: string;
  payload: Record<string, unknown> | null;
  ts: string;
}

interface Stats {
  total_targets: number;
  sent: number;
  opened: number;
  clicked: number;
  submitted: number;
  failed: number;
  open_rate: number;
  click_rate: number;
  submit_rate: number;
  fail_rate: number;
  funnel: { stage: string; count: number }[];
  timeline: { ts: string; event_type: string; ip: string }[];
  top_clickers: {
    id: string;
    email: string;
    name: string;
    clicked_at: string | null;
    submitted_at: string | null;
  }[];
}

const STATUS_CLS: Record<string, string> = {
  draft: "border-gray-500/40 text-gray-300",
  sending: "border-blue-400/40 text-blue-300",
  "in-progress": "border-amber-400/40 text-amber-300",
  completed: "border-emerald-400/40 text-emerald-300",
  failed: "border-red-400/40 text-red-300",
};

const EVENT_CLS: Record<string, string> = {
  email_sent: "text-cyan-glow/80",
  email_opened: "text-emerald-300",
  clicked_link: "text-amber-300",
  submitted_data: "text-red-300",
  email_failed: "text-red-400",
};

type Tab = "targets" | "timeline" | "stats";

export default function CampaignDetail({
  campaignId,
}: {
  campaignId: string;
}) {
  const router = useRouter();
  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [results, setResults] = useState<ResultEvent[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [tab, setTab] = useState<Tab>("targets");
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const r = await fetch(
        `/api/proxy/redteam/phishing/campaigns/${campaignId}`,
        { credentials: "include", cache: "no-store" },
      );
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      setCampaign(d.campaign);
      setTargets(Array.isArray(d.targets) ? d.targets : []);
      setResults(Array.isArray(d.results) ? d.results : []);

      const sr = await fetch(
        `/api/proxy/redteam/phishing/campaigns/${campaignId}/stats`,
        { credentials: "include", cache: "no-store" },
      );
      if (sr.ok) {
        setStats(await sr.json());
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  }, [campaignId]);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function syncNow() {
    setSyncing(true);
    try {
      await fetch(
        `/api/proxy/redteam/phishing/campaigns/${campaignId}/sync`,
        { method: "POST", credentials: "include" },
      );
      await reload();
    } finally {
      setSyncing(false);
    }
  }

  if (loading && !campaign) {
    return (
      <div className="p-6 text-xs tracking-wider text-cyan-glow/70">
        LOADING...
      </div>
    );
  }
  if (err || !campaign) {
    return (
      <div className="p-6 text-xs text-red-400">
        Error: {err ?? "unknown"}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <button
            onClick={() => router.push("/redteam/phishing")}
            className="mb-2 text-[11px] tracking-widest text-cyan-glow/60 hover:text-cyan-glow"
          >
            ← BACK TO CAMPAIGNS
          </button>
          <h1 className="hud-heading text-lg font-bold tracking-widest text-cyan-glow">
            {campaign.name}
          </h1>
          <div className="mt-1 flex items-center gap-3 text-[11px] tracking-wider text-cyan-glow/60">
            <span
              className={`rounded border px-2 py-0.5 ${
                STATUS_CLS[campaign.status] ??
                "border-cyan-glow/40 text-cyan-glow/80"
              }`}
            >
              {campaign.status.toUpperCase()}
            </span>
            <span>TEMPLATE: {campaign.template_name}</span>
            <span>MITRE: {campaign.mitre_technique}</span>
            {campaign.engagement_id && (
              <span>ENGAGEMENT: {campaign.engagement_id.slice(0, 8)}</span>
            )}
            {campaign.last_synced_at && (
              <span>
                SYNCED: {new Date(campaign.last_synced_at).toLocaleString()}
              </span>
            )}
          </div>
        </div>
        <button
          onClick={syncNow}
          disabled={syncing}
          className="rounded border border-cyan-glow/40 bg-cyan-glow/10 px-3 py-1.5 text-xs tracking-widest text-cyan-glow hover:bg-cyan-glow/20 disabled:opacity-40"
        >
          {syncing ? "SYNCING..." : "SYNC NOW"}
        </button>
      </div>

      {/* Big counts */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="TARGETS" value={stats?.total_targets ?? targets.length} tone="cyan" />
        <Stat label="SENT" value={campaign.sent_count} tone="cyan" />
        <Stat label="OPENED" value={campaign.opened_count} tone="emerald" />
        <Stat label="CLICKED" value={campaign.clicked_count} tone="amber" />
        <Stat
          label="SUBMITTED"
          value={campaign.submitted_count}
          tone="red"
        />
      </div>

      {/* Funnel */}
      {stats && <Funnel stats={stats} />}

      {/* Tabs */}
      <div className="mt-2 flex border-b border-cyan-glow/15">
        {(["targets", "timeline", "stats"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-xs tracking-widest ${
              tab === t
                ? "border-b-2 border-cyan-glow text-cyan-glow"
                : "text-cyan-glow/50 hover:text-cyan-glow/80"
            }`}
          >
            {t.toUpperCase()}
          </button>
        ))}
      </div>

      {tab === "targets" && (
        <TargetsTable targets={targets} />
      )}
      {tab === "timeline" && <Timeline results={results} />}
      {tab === "stats" && stats && <StatsPanel stats={stats} />}
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "cyan" | "emerald" | "amber" | "red";
}) {
  const cls = {
    cyan: "text-cyan-glow",
    emerald: "text-emerald-300",
    amber: "text-amber-300",
    red: "text-red-400",
  }[tone];
  return (
    <div className="rounded-md border border-cyan-glow/15 bg-space-dark/60 p-3">
      <p className="text-[10px] tracking-widest text-cyan-glow/50">{label}</p>
      <p className={`mt-1 font-mono text-2xl ${cls}`}>{value}</p>
    </div>
  );
}

function Funnel({ stats }: { stats: Stats }) {
  const max = Math.max(...stats.funnel.map((f) => f.count), 1);
  const colors: Record<string, string> = {
    sent: "bg-cyan-glow/40",
    opened: "bg-emerald-400/50",
    clicked: "bg-amber-400/50",
    submitted: "bg-red-400/50",
  };
  return (
    <div className="rounded-md border border-cyan-glow/15 bg-space-dark/40 p-4">
      <h3 className="mb-3 text-[11px] tracking-widest text-cyan-glow/70">
        FUNNEL
      </h3>
      <div className="flex flex-col gap-2">
        {stats.funnel.map((f) => {
          const pct = (f.count / max) * 100;
          return (
            <div key={f.stage} className="flex items-center gap-3">
              <span className="w-24 text-[11px] uppercase tracking-widest text-cyan-glow/60">
                {f.stage}
              </span>
              <div className="relative h-5 flex-1 overflow-hidden rounded border border-cyan-glow/15 bg-black/30">
                <div
                  className={`h-full ${colors[f.stage] ?? "bg-cyan-glow/40"}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className="w-12 text-right font-mono text-xs text-cyan-glow">
                {f.count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TargetsTable({ targets }: { targets: Target[] }) {
  if (!targets.length) {
    return (
      <div className="rounded-md border border-cyan-glow/15 bg-space-dark/40 p-6 text-center text-xs text-cyan-glow/60">
        No targets yet.
      </div>
    );
  }
  return (
    <div className="overflow-x-auto rounded-md border border-cyan-glow/15 bg-space-dark/40">
      <table className="w-full text-xs">
        <thead className="border-b border-cyan-glow/20 bg-black/20 text-[10px] tracking-widest text-cyan-glow/60">
          <tr>
            <th className="px-3 py-2 text-left">EMAIL</th>
            <th className="px-3 py-2 text-left">NAME</th>
            <th className="px-3 py-2 text-left">POSITION</th>
            <th className="px-3 py-2 text-left">STATUS</th>
            <th className="px-3 py-2 text-left">OPENED</th>
            <th className="px-3 py-2 text-left">CLICKED</th>
            <th className="px-3 py-2 text-left">SUBMITTED</th>
          </tr>
        </thead>
        <tbody>
          {targets.map((t) => (
            <tr
              key={t.id}
              className="border-b border-cyan-glow/10 hover:bg-cyan-glow/5"
            >
              <td className="px-3 py-2 font-mono text-cyan-glow">
                {t.email}
              </td>
              <td className="px-3 py-2 text-cyan-glow/80">
                {`${t.first_name} ${t.last_name}`.trim() || "—"}
              </td>
              <td className="px-3 py-2 text-cyan-glow/60">
                {t.position || "—"}
              </td>
              <td className="px-3 py-2">
                <span
                  className={`rounded border px-2 py-0.5 text-[10px] tracking-widest ${
                    EVENT_CLS[t.last_status] ?? "text-cyan-glow/70"
                  }`}
                >
                  {t.last_status.toUpperCase()}
                </span>
              </td>
              <td className="px-3 py-2 text-emerald-300/80">
                {t.opened_at ? new Date(t.opened_at).toLocaleString() : "—"}
              </td>
              <td className="px-3 py-2 text-amber-300/80">
                {t.clicked_at
                  ? new Date(t.clicked_at).toLocaleString()
                  : "—"}
              </td>
              <td className="px-3 py-2 text-red-400/80">
                {t.submitted_at
                  ? new Date(t.submitted_at).toLocaleString()
                  : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Timeline({ results }: { results: ResultEvent[] }) {
  if (!results.length) {
    return (
      <div className="rounded-md border border-cyan-glow/15 bg-space-dark/40 p-6 text-center text-xs text-cyan-glow/60">
        No events yet. Click SYNC NOW to pull latest from GoPhish.
      </div>
    );
  }
  return (
    <ul className="rounded-md border border-cyan-glow/15 bg-space-dark/40">
      {results.map((r) => (
        <li
          key={r.id}
          className="flex flex-col gap-1 border-b border-cyan-glow/10 px-4 py-2 last:border-b-0"
        >
          <div className="flex items-center justify-between gap-3">
            <span
              className={`text-[11px] tracking-widest ${
                EVENT_CLS[r.event_type] ?? "text-cyan-glow/80"
              }`}
            >
              {r.event_type.toUpperCase()}
            </span>
            <span className="font-mono text-[11px] text-cyan-glow/60">
              {new Date(r.ts).toLocaleString()}
            </span>
          </div>
          {(r.ip_address || r.user_agent) && (
            <div className="text-[10px] text-cyan-glow/50">
              {r.ip_address && <span>{r.ip_address} · </span>}
              <span className="font-mono">{r.user_agent}</span>
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

function StatsPanel({ stats }: { stats: Stats }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div className="rounded-md border border-cyan-glow/15 bg-space-dark/40 p-4">
        <h3 className="mb-3 text-[11px] tracking-widest text-cyan-glow/70">
          RATES
        </h3>
        <div className="flex flex-col gap-2 text-xs">
          <Rate label="OPEN RATE" v={stats.open_rate} tone="emerald" />
          <Rate label="CLICK RATE" v={stats.click_rate} tone="amber" />
          <Rate label="SUBMIT RATE" v={stats.submit_rate} tone="red" />
          <Rate label="FAIL RATE" v={stats.fail_rate} tone="red" />
        </div>
      </div>
      <div className="rounded-md border border-cyan-glow/15 bg-space-dark/40 p-4">
        <h3 className="mb-3 text-[11px] tracking-widest text-cyan-glow/70">
          TOP CLICKERS
        </h3>
        {stats.top_clickers.length === 0 ? (
          <p className="text-xs text-cyan-glow/60">No clicks yet.</p>
        ) : (
          <ul className="flex flex-col gap-1 text-xs">
            {stats.top_clickers.map((c) => (
              <li
                key={c.id}
                className="flex items-center justify-between border-b border-cyan-glow/10 pb-1"
              >
                <span className="font-mono text-cyan-glow">{c.email}</span>
                <span
                  className={
                    c.submitted_at ? "text-red-300" : "text-amber-300"
                  }
                >
                  {c.submitted_at ? "SUBMITTED" : "CLICKED"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Rate({
  label,
  v,
  tone,
}: {
  label: string;
  v: number;
  tone: "emerald" | "amber" | "red";
}) {
  const pct = Math.round(v * 1000) / 10;
  const bar = {
    emerald: "bg-emerald-400/60",
    amber: "bg-amber-400/60",
    red: "bg-red-400/60",
  }[tone];
  return (
    <div className="flex items-center gap-3">
      <span className="w-28 text-[11px] tracking-widest text-cyan-glow/60">
        {label}
      </span>
      <div className="relative h-4 flex-1 overflow-hidden rounded border border-cyan-glow/15 bg-black/30">
        <div className={`h-full ${bar}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-14 text-right font-mono text-cyan-glow">
        {pct}%
      </span>
    </div>
  );
}
