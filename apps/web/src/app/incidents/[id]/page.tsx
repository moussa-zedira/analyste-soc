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
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import { HudHeading, HudCard, HudButton } from "@/components/hud";

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
  const hudVariant = variant === "yellow" ? "secondary" : variant === "green" ? "primary" : "ghost";
  return (
    <HudButton onClick={onClick} disabled={disabled} variant={hudVariant} size="sm">
      <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
      </svg>
      {children}
    </HudButton>
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
        <HudCard tone="alert" className="px-4 py-3 text-sm text-neon-pink">
          <span className="mr-2">&#x25B2;</span>
          {error}
        </HudCard>
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
    <PageTransition className="space-y-6">
      {/* Header */}
      <StaggerItem>
        <div className="flex items-center gap-3">
          <HudButton variant="secondary" size="sm" className="px-2.5" onClick={() => router.push("/incidents")}>
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
            </svg>
          </HudButton>
          <HudHeading level={2}>{incident.title}</HudHeading>
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
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Detail card */}
      <StaggerItem>
        <HudCard className="glass-panel-animated p-6">
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
                {incident.dedup_hash ? `${incident.dedup_hash.slice(0, 16)}...` : "-"}
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
        </HudCard>
      </StaggerItem>

      {/* Events */}
      <StaggerItem>
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="hud-heading text-base font-bold tracking-wider text-cyan-glow">
              Related Events
              <span className="ml-2 rounded-full border border-cyan-glow/20 bg-cyan-glow/10 px-2 py-0.5 text-[10px] font-normal tracking-wider text-cyan-glow">
                {incident.events?.length ?? 0}
              </span>
            </h2>
            <div className="flex gap-2">
              <HudButton
                size="sm"
                variant={eventsView === "timeline" ? "primary" : "ghost"}
                onClick={() => setEventsView("timeline")}
              >
                TIMELINE
              </HudButton>
              <HudButton
                size="sm"
                variant={eventsView === "table" ? "primary" : "ghost"}
                onClick={() => setEventsView("table")}
              >
                TABLE
              </HudButton>
            </div>
          </div>

          {eventsView === "timeline" ? (
            <HudCard className="p-5">
              <IncidentTimeline events={incident.events ?? []} />
            </HudCard>
          ) : (
            <HudCard className="overflow-hidden p-0">
              <DataTable
                columns={eventColumns}
                data={incident.events ?? []}
                loading={false}
                error={null}
              />
            </HudCard>
          )}
        </div>
      </StaggerItem>
    </PageTransition>
  );
}
