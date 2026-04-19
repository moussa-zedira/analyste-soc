"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";

type Tab =
  | "overview"
  | "nodes"
  | "kerberoastable"
  | "asreproastable"
  | "unconstrained"
  | "highvalue";

interface BHNode {
  sid: string;
  name: string;
  object_type: string;
  domain: string;
  high_value: boolean;
  props?: Record<string, unknown>;
}

interface DatasetDetail {
  dataset: {
    id: string;
    name: string;
    source_filename: string;
    engagement_id: string | null;
    bh_schema_version: number;
    nodes_count: number;
    edges_count: number;
    uploaded_at: string;
    notes: string;
  };
  stats: {
    nodes_by_type: Record<string, number>;
    high_value_count: number;
    edges_by_type: Record<string, number>;
  };
  top_high_value: BHNode[];
}

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "OVERVIEW" },
  { id: "nodes", label: "NODES" },
  { id: "kerberoastable", label: "KERBEROASTABLE" },
  { id: "asreproastable", label: "ASREP-ROASTABLE" },
  { id: "unconstrained", label: "UNCONSTRAINED DELEG" },
  { id: "highvalue", label: "HIGH VALUE" },
];

export default function DatasetView({ datasetId }: { datasetId: string }) {
  const [tab, setTab] = useState<Tab>("overview");
  const [detail, setDetail] = useState<DatasetDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setErr(null);
      try {
        const res = await fetch(
          `/api/proxy/redteam/bloodhound/datasets/${datasetId}`,
          { credentials: "include", cache: "no-store" },
        );
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as DatasetDetail;
        if (!cancelled) setDetail(data);
      } catch (e) {
        if (!cancelled) setErr(String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [datasetId]);

  if (loading) {
    return (
      <div className="p-6 text-xs tracking-widest text-cyan-glow/40">
        LOADING DATASET...
      </div>
    );
  }
  if (err || !detail) {
    return (
      <div className="p-6 text-xs text-red-400">
        Failed to load dataset: {err}
      </div>
    );
  }

  const ds = detail.dataset;

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex items-start justify-between gap-3">
        <div>
          <Link
            href="/redteam/bloodhound"
            className="mb-1 block text-[10px] tracking-widest text-cyan-glow/40 hover:text-cyan-glow/80"
          >
            &lt; BACK TO DATASETS
          </Link>
          <h1 className="hud-heading text-lg font-bold tracking-widest text-cyan-glow">
            {ds.name}
          </h1>
          <p className="text-[11px] tracking-wider text-cyan-glow/50">
            {ds.nodes_count} NODES // {ds.edges_count} EDGES // BH SCHEMA v
            {ds.bh_schema_version} // UPLOADED{" "}
            {new Date(ds.uploaded_at).toLocaleString()}
          </p>
          {ds.engagement_id && (
            <p className="text-[11px] tracking-wider text-cyan-glow/50">
              ENGAGEMENT: {ds.engagement_id}
            </p>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-1 border-b border-cyan-glow/15">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-2 text-[11px] tracking-widest ${
              tab === t.id
                ? "border-b-2 border-cyan-glow text-cyan-glow"
                : "text-cyan-glow/50 hover:text-cyan-glow/80"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="rounded-md border border-cyan-glow/15 bg-space-dark/60 p-4">
        {tab === "overview" && <OverviewPanel detail={detail} />}
        {tab === "nodes" && <NodesPanel datasetId={datasetId} />}
        {tab === "kerberoastable" && (
          <ListPanel
            datasetId={datasetId}
            endpoint="kerberoastable"
            title="Users with SPN (Kerberoastable)"
          />
        )}
        {tab === "asreproastable" && (
          <ListPanel
            datasetId={datasetId}
            endpoint="asreproastable"
            title="Users with DontReqPreAuth (ASREP-roastable)"
          />
        )}
        {tab === "unconstrained" && (
          <ListPanel
            datasetId={datasetId}
            endpoint="unconstrained-delegation"
            title="Unconstrained delegation"
          />
        )}
        {tab === "highvalue" && (
          <ListPanel
            datasetId={datasetId}
            endpoint="high-value-targets"
            title="High value targets"
          />
        )}
      </div>
    </div>
  );
}

function OverviewPanel({ detail }: { detail: DatasetDetail }) {
  const types = Object.entries(detail.stats?.nodes_by_type ?? {});
  const edges = Object.entries(detail.stats?.edges_by_type ?? {}).sort(
    (a, b) => b[1] - a[1],
  );
  return (
    <div className="grid gap-6 md:grid-cols-2">
      <section>
        <h3 className="mb-2 text-xs tracking-widest text-cyan-glow/70">
          NODES BY TYPE
        </h3>
        <ul className="text-sm">
          {types.map(([k, v]) => (
            <li
              key={k}
              className="flex justify-between border-b border-cyan-glow/10 py-1 text-cyan-glow/80"
            >
              <span>{k}</span>
              <span className="font-mono">{v}</span>
            </li>
          ))}
          <li className="mt-2 flex justify-between rounded bg-cyan-glow/10 px-2 py-1 text-cyan-glow">
            <span>HIGH VALUE</span>
            <span className="font-mono">{detail.stats?.high_value_count ?? 0}</span>
          </li>
        </ul>
      </section>
      <section>
        <h3 className="mb-2 text-xs tracking-widest text-cyan-glow/70">
          EDGES BY TYPE (TOP)
        </h3>
        <ul className="max-h-72 overflow-y-auto text-sm">
          {edges.slice(0, 25).map(([k, v]) => (
            <li
              key={k}
              className="flex justify-between border-b border-cyan-glow/10 py-1 text-cyan-glow/80"
            >
              <span>{k}</span>
              <span className="font-mono">{v}</span>
            </li>
          ))}
        </ul>
      </section>
      <section className="md:col-span-2">
        <h3 className="mb-2 text-xs tracking-widest text-cyan-glow/70">
          TOP 10 HIGH VALUE
        </h3>
        <ul className="text-sm">
          {(detail.top_high_value ?? []).map((n) => (
            <li
              key={n.sid}
              className="flex justify-between border-b border-cyan-glow/10 py-1"
            >
              <span className="text-cyan-glow">{n.name}</span>
              <span className="text-xs text-cyan-glow/50">
                {n.object_type}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function NodesPanel({ datasetId }: { datasetId: string }) {
  const [nodes, setNodes] = useState<BHNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [type, setType] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const params = new URLSearchParams();
    params.set("limit", "200");
    if (type) params.set("object_type", type);
    if (filter) params.set("name", filter);
    fetch(
      `/api/proxy/redteam/bloodhound/datasets/${datasetId}/nodes?${params.toString()}`,
      { credentials: "include", cache: "no-store" },
    )
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => {
        if (!cancelled) setNodes(Array.isArray(d) ? d : []);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [datasetId, filter, type]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-2">
        <input
          type="text"
          placeholder="search by name..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 text-sm text-cyan-glow"
        />
        <select
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 text-sm text-cyan-glow"
        >
          <option value="">all types</option>
          {["User", "Computer", "Group", "Domain", "OU", "GPO"].map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
      </div>
      {loading ? (
        <p className="text-xs text-cyan-glow/40">LOADING...</p>
      ) : (
        <NodeList nodes={nodes} />
      )}
    </div>
  );
}

function ListPanel({
  datasetId,
  endpoint,
  title,
}: {
  datasetId: string;
  endpoint: string;
  title: string;
}) {
  const [nodes, setNodes] = useState<BHNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetch(
      `/api/proxy/redteam/bloodhound/datasets/${datasetId}/${endpoint}`,
      { credentials: "include", cache: "no-store" },
    )
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => {
        if (!cancelled) setNodes(Array.isArray(d) ? d : []);
      })
      .catch((e) => {
        if (!cancelled) setErr(String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [datasetId, endpoint]);
  return (
    <div className="flex flex-col gap-3">
      <h3 className="text-xs tracking-widest text-cyan-glow/70">
        {title.toUpperCase()} ({nodes.length})
      </h3>
      {loading && (
        <p className="text-xs text-cyan-glow/40">LOADING...</p>
      )}
      {err && <p className="text-xs text-red-400">{err}</p>}
      {!loading && !err && <NodeList nodes={nodes} />}
    </div>
  );
}

function NodeList({ nodes }: { nodes: BHNode[] }) {
  if (!nodes.length) {
    return (
      <p className="text-xs text-cyan-glow/40">NO RESULTS.</p>
    );
  }
  return (
    <table className="w-full text-left text-sm">
      <thead className="border-b border-cyan-glow/10 text-[10px] uppercase text-cyan-glow/40">
        <tr>
          <th className="px-2 py-1">NAME</th>
          <th className="px-2 py-1">TYPE</th>
          <th className="px-2 py-1">DOMAIN</th>
          <th className="px-2 py-1">FLAGS</th>
        </tr>
      </thead>
      <tbody>
        {nodes.map((n) => (
          <tr
            key={n.sid}
            className="border-b border-cyan-glow/5 hover:bg-cyan-glow/5"
          >
            <td className="px-2 py-1 text-cyan-glow">{n.name}</td>
            <td className="px-2 py-1 text-xs text-cyan-glow/70">
              {n.object_type}
            </td>
            <td className="px-2 py-1 text-xs text-cyan-glow/50">
              {n.domain}
            </td>
            <td className="px-2 py-1 text-[10px] tracking-wider text-cyan-glow/70">
              {n.high_value && (
                <span className="mr-1 rounded bg-amber-500/20 px-1 text-amber-300">
                  HV
                </span>
              )}
              {(n.props as Record<string, unknown>)?.has_spn === true && (
                <span className="mr-1 rounded bg-cyan-glow/20 px-1">
                  SPN
                </span>
              )}
              {(n.props as Record<string, unknown>)?.asrep_roastable ===
                true && (
                <span className="mr-1 rounded bg-fuchsia-500/20 px-1 text-fuchsia-300">
                  ASREP
                </span>
              )}
              {(n.props as Record<string, unknown>)
                ?.unconstraineddelegation === true && (
                <span className="mr-1 rounded bg-red-500/20 px-1 text-red-300">
                  UNC-DELEG
                </span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
