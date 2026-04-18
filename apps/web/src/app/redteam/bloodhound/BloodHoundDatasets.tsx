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

interface Dataset {
  id: string;
  name: string;
  source_filename: string;
  engagement_id: string | null;
  bh_schema_version: number;
  nodes_count: number;
  edges_count: number;
  uploaded_by: string | null;
  uploaded_at: string;
  notes: string;
}

export default function BloodHoundDatasets() {
  const router = useRouter();
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [showUpload, setShowUpload] = useState(false);

  async function reload() {
    setLoading(true);
    setErr(null);
    try {
      const res = await fetch("/api/proxy/redteam/bloodhound/datasets", {
        credentials: "include",
        cache: "no-store",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setDatasets(Array.isArray(data) ? data : []);
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void reload();
    // engagements pour l'affichage
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

  const columns: Column<Dataset>[] = [
    {
      header: "NAME",
      accessor: (d) => (
        <span className="font-medium text-cyan-glow">{d.name}</span>
      ),
      sortValue: (d) => d.name,
    },
    {
      header: "ENGAGEMENT",
      accessor: (d) => (
        <span className="text-cyan-glow/70">
          {engagementName(d.engagement_id)}
        </span>
      ),
      sortValue: (d) => d.engagement_id ?? "",
    },
    {
      header: "NODES",
      accessor: (d) => (
        <span className="font-mono text-cyan-glow/80">{d.nodes_count}</span>
      ),
      sortValue: (d) => d.nodes_count,
    },
    {
      header: "EDGES",
      accessor: (d) => (
        <span className="font-mono text-cyan-glow/80">{d.edges_count}</span>
      ),
      sortValue: (d) => d.edges_count,
    },
    {
      header: "UPLOADED",
      accessor: (d) => (
        <span className="text-xs text-cyan-glow/60">
          {new Date(d.uploaded_at).toLocaleString()}
        </span>
      ),
      sortValue: (d) => d.uploaded_at,
    },
    {
      header: "FILE",
      accessor: (d) => (
        <span
          className="block max-w-[18rem] truncate text-xs text-cyan-glow/40"
          title={d.source_filename}
        >
          {d.source_filename || "—"}
        </span>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-lg font-bold tracking-widest text-cyan-glow">
            BLOODHOUND DATASETS
          </h1>
          <p className="text-[11px] tracking-wider text-cyan-glow/50">
            DUMPS AD // CHEMINS D'ATTAQUE THEORIQUES // READ-ONLY
          </p>
        </div>
        <button
          onClick={() => setShowUpload(true)}
          className="rounded border border-cyan-glow/40 bg-cyan-glow/10 px-3 py-1.5 text-xs tracking-widest text-cyan-glow hover:bg-cyan-glow/20"
        >
          + UPLOAD ZIP
        </button>
      </div>

      <div className="rounded-md border border-cyan-glow/15 bg-space-dark/60">
        <DataTable<Dataset>
          columns={columns}
          data={datasets}
          loading={loading}
          error={err}
          onRowClick={(d) => router.push(`/redteam/bloodhound/${d.id}`)}
        />
      </div>

      {showUpload && (
        <UploadModal
          engagements={engagements}
          onClose={() => setShowUpload(false)}
          onUploaded={() => {
            setShowUpload(false);
            void reload();
          }}
        />
      )}
    </div>
  );
}

function UploadModal({
  engagements,
  onClose,
  onUploaded,
}: {
  engagements: Engagement[];
  onClose: () => void;
  onUploaded: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [engagementId, setEngagementId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!file || !name) {
      setError("Name and file required.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("name", name);
      if (engagementId) fd.append("engagement_id", engagementId);
      const res = await fetch("/api/proxy/redteam/bloodhound/datasets", {
        method: "POST",
        body: fd,
        credentials: "include",
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`HTTP ${res.status} ${txt.slice(0, 200)}`);
      }
      onUploaded();
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur">
      <div className="w-full max-w-md rounded-md border border-cyan-glow/30 bg-space-dark p-5">
        <h2 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow">
          UPLOAD BLOODHOUND DUMP
        </h2>
        <div className="flex flex-col gap-3">
          <label className="flex flex-col gap-1 text-xs tracking-wider text-cyan-glow/70">
            DATASET NAME
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="ACME prod 2026-04-18"
              className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 text-sm text-cyan-glow"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs tracking-wider text-cyan-glow/70">
            ENGAGEMENT (OPTIONAL)
            <select
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 text-sm text-cyan-glow"
            >
              <option value="">— none —</option>
              {engagements.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.name} · {e.client_name}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs tracking-wider text-cyan-glow/70">
            BLOODHOUND ZIP (.zip)
            <input
              type="file"
              accept=".zip,application/zip"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="text-sm text-cyan-glow"
            />
          </label>
          {error && (
            <p className="break-words text-xs text-red-400">{error}</p>
          )}
          <div className="mt-2 flex justify-end gap-2">
            <button
              onClick={onClose}
              className="rounded border border-cyan-glow/20 px-3 py-1 text-xs tracking-widest text-cyan-glow/70 hover:bg-cyan-glow/10"
            >
              CANCEL
            </button>
            <button
              onClick={submit}
              disabled={submitting}
              className="rounded border border-cyan-glow/40 bg-cyan-glow/10 px-3 py-1 text-xs tracking-widest text-cyan-glow hover:bg-cyan-glow/20 disabled:opacity-40"
            >
              {submitting ? "UPLOADING..." : "UPLOAD"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
