"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { getIncident, updateIncidentStatus } from "@/lib/apiClient";
import { eventColumns } from "@/lib/columns";
import { useFetchData } from "@/lib/hooks";
import type { IncidentDetail, IncidentStatus } from "@/lib/types";
import { SeverityBadge, StatusBadge } from "@/components/Badge";
import { SuggestedSeverityBadge } from "@/components/SuggestedSeverityBadge";
import { DataTable } from "@/components/DataTable";
import { IncidentTimeline } from "@/components/IncidentTimeline";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="hud-label">{label}</dt>
      <dd className="mt-1 text-sm text-gray-300">{children}</dd>
    </div>
  );
}

function ActionButton({
  onClick,
  disabled,
  variant,
  icon,
  children,
}: {
  onClick: () => void;
  disabled: boolean;
  variant: "yellow" | "green" | "gray";
  icon: string;
  children: React.ReactNode;
}) {
  const colors = {
    yellow: "border-yellow-500/30 bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20",
    green: "border-cyan-glow/30 bg-cyan-glow/10 text-cyan-glow hover:bg-cyan-glow/20",
    gray: "border-gray-600 bg-space-mid/50 text-gray-400 hover:bg-space-mid hover:text-gray-200",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`flex items-center gap-1.5 rounded-md border px-3.5 py-2 text-[10px] font-bold tracking-wider transition-all duration-150 active:scale-95 disabled:opacity-50 ${colors[variant]}`}
    >
      <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
      </svg>
      {children}
    </button>
  );
}

function DetailSkeleton() {
  return (
    <div className="animate-fade-in space-y-6">
      <div className="flex items-center gap-3">
        <div className="skeleton h-8 w-16 rounded-lg" />
        <div className="skeleton h-7 w-72" />
      </div>
      <div className="glass-panel p-5">
        <div className="grid grid-cols-2 gap-x-8 gap-y-4 sm:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i}>
              <div className="skeleton mb-2 h-3 w-16" />
              <div className="skeleton h-5 w-24" />
            </div>
          ))}
        </div>
        <div className="mt-4 border-t border-cyan-glow/10 pt-4">
          <div className="skeleton mb-2 h-3 w-20" />
          <div className="skeleton h-4 w-full" />
          <div className="skeleton mt-1 h-4 w-3/4" />
        </div>
      </div>
      <div className="glass-panel p-5">
        <div className="skeleton h-5 w-40" />
      </div>
    </div>
  );
}

/** Page de detail d'un incident avec actions de gestion et evenements associes. */
export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const [eventsView, setEventsView] = useState<"timeline" | "table">("timeline");
  const [refreshKey, setRefreshKey] = useState(0);
  const [updating, setUpdating] = useState(false);

  const { data: incident, loading, error } = useFetchData(
    (signal) => getIncident(params.id, { signal }),
    null as IncidentDetail | null,
    [params.id, refreshKey],
  );

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    setUpdating(true);
    try {
      await updateIncidentStatus(params.id, newStatus);
      setRefreshKey((k) => k + 1);
    } catch {
      /* error handled by re-fetch */
    } finally {
      setUpdating(false);
    }
  };

  if (loading) return <DetailSkeleton />;

  if (error) {
    return (
      <div className="animate-fade-in space-y-4">
        <div className="glass-panel border-red-500/30 px-4 py-3 text-sm text-red-400">
          <span className="mr-2">&#x25B2;</span>
          {error}
        </div>
        <button
          onClick={() => router.push("/incidents")}
          className="text-sm text-cyan-glow underline"
        >
          Back to incidents
        </button>
      </div>
    );
  }

  if (!incident) return null;

  return (
    <div className="animate-fade-in space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => router.push("/incidents")}
          className="rounded-md border border-cyan-glow/20 bg-space-mid/50 px-2.5 py-1.5 text-gray-400 transition-all hover:border-cyan-glow/40 hover:bg-cyan-glow/10 hover:text-cyan-glow active:scale-95"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
          </svg>
        </button>
        <h1 className="hud-heading text-lg font-bold tracking-wider text-cyan-glow">
          {incident.title}
        </h1>
        <div className="ml-auto flex gap-2">
          {incident.status === "open" && (
            <>
              <ActionButton onClick={() => handleStatusChange("ack")} disabled={updating} variant="yellow" icon="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z">
                ACKNOWLEDGE
              </ActionButton>
              <ActionButton onClick={() => handleStatusChange("closed")} disabled={updating} variant="green" icon="M4.5 12.75l6 6 9-13.5">
                CLOSE
              </ActionButton>
            </>
          )}
          {incident.status === "ack" && (
            <>
              <ActionButton onClick={() => handleStatusChange("closed")} disabled={updating} variant="green" icon="M4.5 12.75l6 6 9-13.5">
                CLOSE
              </ActionButton>
              <ActionButton onClick={() => handleStatusChange("open")} disabled={updating} variant="gray" icon="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99">
                REOPEN
              </ActionButton>
            </>
          )}
          {incident.status === "closed" && (
            <ActionButton onClick={() => handleStatusChange("open")} disabled={updating} variant="gray" icon="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99">
              REOPEN
            </ActionButton>
          )}
        </div>
      </div>

      <div className="cyan-line" />

      {/* Detail card */}
      <div className="glass-panel glass-panel-animated p-6">
        <dl className="grid grid-cols-2 gap-x-8 gap-y-5 sm:grid-cols-4">
          <Field label="Status">
            <StatusBadge value={incident.status} />
          </Field>
          <Field label="Severity">
            <div className="flex items-center gap-2">
              <SeverityBadge value={incident.severity} />
              <SuggestedSeverityBadge
                actual={incident.severity}
                suggested={incident.suggested_severity}
              />
            </div>
          </Field>
          <Field label="Rule">
            <span className="rounded-md border border-cyan-glow/15 bg-space-mid/50 px-1.5 py-0.5 font-mono text-xs text-cyan-dim">
              {incident.rule_id}
            </span>
          </Field>
          <Field label="Entity">
            <span className="rounded-md border border-cyan-glow/15 bg-space-mid/50 px-1.5 py-0.5 font-mono text-xs text-cyan-glow/60">
              {incident.entity_key}
            </span>
          </Field>
          <Field label="Created">
            <span className="font-mono text-xs text-cyan-glow/60">
              {new Date(incident.created_at).toLocaleString()}
            </span>
          </Field>
          <Field label="Window start">
            <span className="font-mono text-xs text-cyan-glow/60">
              {new Date(incident.start_ts).toLocaleString()}
            </span>
          </Field>
          <Field label="Window end">
            <span className="font-mono text-xs text-cyan-glow/60">
              {new Date(incident.end_ts).toLocaleString()}
            </span>
          </Field>
          <Field label="Dedup hash">
            <span className="font-mono text-xs text-gray-500">
              {incident.dedup_hash.slice(0, 16)}...
            </span>
          </Field>
        </dl>
        {incident.description && (
          <div className="mt-5 border-t border-cyan-glow/10 pt-5">
            <p className="hud-label mb-1.5">Description</p>
            <p className="text-sm leading-relaxed text-gray-300">
              {incident.description}
            </p>
          </div>
        )}
      </div>

      {/* Events */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="hud-heading text-base font-bold tracking-wider text-cyan-glow">
            Related Events
            <span className="ml-2 rounded-full border border-cyan-glow/20 bg-cyan-glow/10 px-2 py-0.5 text-[10px] font-normal tracking-wider text-cyan-glow">
              {incident.events?.length ?? 0}
            </span>
          </h2>
          <div className="flex overflow-hidden rounded-md border border-cyan-glow/20 text-[10px] font-bold tracking-wider">
            <button
              onClick={() => setEventsView("timeline")}
              className={`px-3.5 py-1.5 transition-all duration-150 ${
                eventsView === "timeline"
                  ? "bg-cyan-glow/15 text-cyan-glow"
                  : "bg-space-mid/50 text-gray-500 hover:text-gray-300"
              }`}
            >
              TIMELINE
            </button>
            <button
              onClick={() => setEventsView("table")}
              className={`px-3.5 py-1.5 transition-all duration-150 ${
                eventsView === "table"
                  ? "bg-cyan-glow/15 text-cyan-glow"
                  : "bg-space-mid/50 text-gray-500 hover:text-gray-300"
              }`}
            >
              TABLE
            </button>
          </div>
        </div>

        {eventsView === "timeline" ? (
          <div className="glass-panel p-5">
            <IncidentTimeline events={incident.events ?? []} />
          </div>
        ) : (
          <div className="glass-panel overflow-hidden">
            <DataTable
              columns={eventColumns}
              data={incident.events ?? []}
              loading={false}
              error={null}
            />
          </div>
        )}
      </div>
    </div>
  );
}
