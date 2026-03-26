"use client";

import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { listIncidents } from "@/lib/apiClient";
import { DEFAULT_LIMIT, SEVERITY_OPTIONS, STATUS_OPTIONS } from "@/lib/constants";
import { readInt, readParam, useFetchData, usePushParams } from "@/lib/hooks";
import type { Incident } from "@/lib/types";
import { SeverityBadge, StatusBadge } from "@/components/Badge";
import { DataTable, type Column } from "@/components/DataTable";
import { FilterBar, FilterSelect } from "@/components/FilterBar";
import { Pagination } from "@/components/Pagination";

const columns: Column<Incident>[] = [
  {
    header: "Created",
    accessor: (r) => (
      <span className="whitespace-nowrap text-gray-400">
        {new Date(r.created_at).toLocaleString()}
      </span>
    ),
  },
  {
    header: "Status",
    accessor: (r) => <StatusBadge value={r.status} />,
  },
  {
    header: "Severity",
    accessor: (r) => <SeverityBadge value={r.severity} />,
  },
  {
    header: "Title",
    accessor: (r) => (
      <span className="block max-w-sm truncate font-medium text-gray-900 dark:text-white">
        {r.title}
      </span>
    ),
  },
  { header: "Rule", accessor: (r) => r.rule_id },
  { header: "Entity", accessor: (r) => r.entity_key },
];

function IncidentsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pushParams = usePushParams("/incidents");

  const limit = readInt(searchParams, "limit", DEFAULT_LIMIT);
  const offset = readInt(searchParams, "offset", 0);
  const severity = readParam(searchParams, "severity", "");
  const statusFilter = readParam(searchParams, "status_filter", "");

  const { data, loading, error } = useFetchData(
    (signal) =>
      listIncidents(
        {
          limit,
          offset,
          ...(severity ? { severity } : {}),
          ...(statusFilter ? { status_filter: statusFilter } : {}),
        },
        { signal },
      ),
    [],
    [limit, offset, severity, statusFilter],
  );

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Incidents</h1>

      <FilterBar onReset={() => router.push("/incidents")}>
        <FilterSelect
          label="Severity"
          value={severity}
          options={SEVERITY_OPTIONS}
          onChange={(v) => pushParams({ severity: v, offset: 0 })}
        />
        <FilterSelect
          label="Status"
          value={statusFilter}
          options={STATUS_OPTIONS}
          onChange={(v) => pushParams({ status_filter: v, offset: 0 })}
        />
      </FilterBar>

      <div className="rounded-lg border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
        <DataTable
          columns={columns}
          data={data}
          loading={loading}
          error={error}
          onRowClick={(row) => router.push(`/incidents/${row.id}`)}
        />
        {!loading && !error && (
          <div className="px-3 pb-3">
            <Pagination
              offset={offset}
              limit={limit}
              count={data.length}
              onChange={(o) => pushParams({ offset: o })}
            />
          </div>
        )}
      </div>
    </div>
  );
}

export default function IncidentsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex h-40 items-center justify-center text-gray-500">
          Loading...
        </div>
      }
    >
      <IncidentsContent />
    </Suspense>
  );
}
