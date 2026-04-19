"use client";

import { useEffect, useMemo, useState } from "react";
import type { SliverSessionDTO } from "./OperatorConsole";

interface NodeRef {
  sid: string;
  name: string;
  object_type: string;
  domain?: string;
  high_value?: boolean;
}

interface PathEdge {
  from: string;
  to: string;
  type: string;
}

interface AttackPath {
  target: NodeRef;
  hops: number;
  edges: PathEdge[];
}

interface PivotResult {
  host: NodeRef | null;
  user: NodeRef | null;
  local_admins_on_host: NodeRef[];
  logged_users_on_host: NodeRef[];
  paths_from_host_to_high_value: AttackPath[];
  paths_from_user_to_high_value: AttackPath[];
}

interface DatasetSummary {
  id: string;
  name: string;
  engagement_id: string | null;
}

interface Props {
  session: SliverSessionDTO | null;
  engagementId: string | null;
}

export default function BloodHoundPivot({ session, engagementId }: Props) {
  const [collapsed, setCollapsed] = useState(false);
  const [datasets, setDatasets] = useState<DatasetSummary[]>([]);
  const [datasetId, setDatasetId] = useState<string>("");
  const [result, setResult] = useState<PivotResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Reload datasets quand l'engagement change.
  useEffect(() => {
    setResult(null);
    if (!engagementId) {
      setDatasets([]);
      setDatasetId("");
      return;
    }
    fetch(
      `/api/proxy/redteam/bloodhound/datasets?engagement_id=${encodeURIComponent(engagementId)}`,
      { credentials: "include", cache: "no-store" },
    )
      .then((r) => (r.ok ? r.json() : []))
      .then((d: DatasetSummary[]) => {
        const list = Array.isArray(d) ? d : [];
        setDatasets(list);
        if (list.length > 0) {
          setDatasetId(list[0].id);
        } else {
          setDatasetId("");
        }
      })
      .catch(() => setDatasets([]));
  }, [engagementId]);

  // Lance un pivot a chaque nouvelle session ou changement de dataset.
  useEffect(() => {
    if (!datasetId || !session?.hostname) {
      setResult(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErr(null);
    fetch(
      `/api/proxy/redteam/bloodhound/datasets/${datasetId}/pivot-from-session`,
      {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: session.id,
          hostname: session.hostname,
          username: session.username,
          max_hops: 5,
          max_paths: 15,
        }),
      },
    )
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: PivotResult) => {
        if (!cancelled) setResult(d);
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
  }, [datasetId, session?.id, session?.hostname, session?.username]);

  if (!engagementId) return null;
  if (datasets.length === 0) {
    return (
      <div className="rounded-md border border-cyan-glow/15 bg-space-dark/60 p-3">
        <p className="text-[10px] tracking-widest text-cyan-glow/40">
          BLOODHOUND PIVOT // NO DATASET FOR THIS ENGAGEMENT
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-md border border-cyan-glow/15 bg-space-dark/60">
      <button
        onClick={() => setCollapsed((c) => !c)}
        className="flex w-full items-center justify-between border-b border-cyan-glow/10 px-3 py-2 text-left"
      >
        <span className="hud-label text-[10px] tracking-widest text-cyan-glow/60">
          BLOODHOUND PIVOT (READ-ONLY)
        </span>
        <span className="text-[10px] tracking-widest text-cyan-glow/40">
          {collapsed ? "+" : "−"}
        </span>
      </button>
      {!collapsed && (
        <div className="flex flex-col gap-3 p-3">
          <div className="flex items-center gap-2">
            <span className="text-[10px] tracking-widest text-cyan-glow/50">
              DATASET
            </span>
            <select
              value={datasetId}
              onChange={(e) => setDatasetId(e.target.value)}
              className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 text-xs text-cyan-glow"
            >
              {datasets.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}
                </option>
              ))}
            </select>
          </div>

          {!session && (
            <p className="text-[11px] text-cyan-glow/40">
              Select a session to see suggested pivots.
            </p>
          )}
          {session && loading && (
            <p className="text-[11px] tracking-wider text-cyan-glow/40">
              COMPUTING PATHS...
            </p>
          )}
          {err && (
            <p className="break-words text-[11px] text-red-400">{err}</p>
          )}
          {session && result && (
            <PivotContent result={result} session={session} />
          )}
        </div>
      )}
    </div>
  );
}

function PivotContent({
  result,
  session,
}: {
  result: PivotResult;
  session: SliverSessionDTO;
}) {
  if (!result.host) {
    return (
      <p className="text-[11px] text-cyan-glow/40">
        Host <span className="text-cyan-glow">{session.hostname}</span> not
        found in this BH dataset.
      </p>
    );
  }
  const pathsHost = result.paths_from_host_to_high_value ?? [];
  const pathsUser = result.paths_from_user_to_high_value ?? [];
  const localAdmins = result.local_admins_on_host ?? [];
  const loggedUsers = result.logged_users_on_host ?? [];
  return (
    <div className="flex flex-col gap-3 text-[11px]">
      <div>
        <p className="mb-1 text-cyan-glow/60">
          PATHS FROM HOST → HIGH VALUE (
          {pathsHost.length})
        </p>
        <PathList paths={pathsHost} />
      </div>
      {result.user && (
        <div>
          <p className="mb-1 text-cyan-glow/60">
            PATHS FROM USER ({result.user.name}) → HIGH VALUE (
            {pathsUser.length})
          </p>
          <PathList paths={pathsUser} />
        </div>
      )}
      <div>
        <p className="mb-1 text-cyan-glow/60">
          LOCAL ADMINS ON HOST ({localAdmins.length})
        </p>
        <NodeChipList nodes={localAdmins} />
      </div>
      <div>
        <p className="mb-1 text-cyan-glow/60">
          LOGGED USERS ON HOST ({loggedUsers.length})
        </p>
        <NodeChipList nodes={loggedUsers} />
      </div>
    </div>
  );
}

function PathList({ paths }: { paths: AttackPath[] }) {
  const list = paths ?? [];
  if (!list.length) {
    return <p className="text-cyan-glow/30">none</p>;
  }
  return (
    <ul className="flex flex-col gap-1">
      {list.map((p, i) => (
        <li
          key={i}
          className="rounded border border-cyan-glow/10 bg-black/30 p-2"
        >
          <div className="flex items-center justify-between">
            <span className="text-cyan-glow">{p.target.name}</span>
            <span className="rounded bg-amber-500/20 px-1 text-[9px] text-amber-300">
              {p.hops} HOPS
            </span>
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {(p.edges ?? []).map((e, j) => (
              <span
                key={j}
                className="rounded border border-cyan-glow/10 bg-cyan-glow/5 px-1 text-[9px] text-cyan-glow/70"
              >
                {e.type}
              </span>
            ))}
          </div>
          <button
            onClick={() => copyPathAsNote(p)}
            className="mt-1 text-[9px] tracking-widest text-cyan-glow/50 hover:text-cyan-glow"
          >
            COPY AS NOTE
          </button>
        </li>
      ))}
    </ul>
  );
}

function NodeChipList({ nodes }: { nodes: NodeRef[] }) {
  const list = nodes ?? [];
  if (!list.length) {
    return <p className="text-cyan-glow/30 text-[11px]">none</p>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {list.map((n) => (
        <span
          key={n.sid}
          className="rounded border border-cyan-glow/15 bg-black/30 px-2 py-0.5 text-[10px] text-cyan-glow/80"
          title={n.sid}
        >
          {n.name}
          <span className="ml-1 text-cyan-glow/40">({n.object_type})</span>
          {n.high_value && (
            <span className="ml-1 text-amber-300">HV</span>
          )}
        </span>
      ))}
    </div>
  );
}

function copyPathAsNote(p: AttackPath) {
  const lines = [
    `BloodHound path -> ${p.target.name} (${p.target.object_type}) in ${p.hops} hops`,
    ...(p.edges ?? []).map((e, i) => `  ${i + 1}. ${e.from} --[${e.type}]--> ${e.to}`),
  ];
  const text = lines.join("\n");
  if (typeof navigator !== "undefined" && navigator.clipboard) {
    navigator.clipboard.writeText(text).catch(() => {});
  }
}
