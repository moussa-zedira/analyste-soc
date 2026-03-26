import type { Column } from "@/components/DataTable";
import { SeverityBadge } from "@/components/Badge";
import type { Event } from "./types";

const SEVERITY_RANK: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/** Definition des colonnes du tableau des evenements de securite. */
export const eventColumns: Column<Event>[] = [
  {
    header: "Timestamp",
    accessor: (r) => (
      <span className="whitespace-nowrap font-mono text-xs text-cyan-glow/60">
        {new Date(r.ts).toLocaleString()}
      </span>
    ),
    sortValue: (r) => r.ts,
  },
  {
    header: "Source",
    accessor: (r) => (
      <span className="text-gray-400">{r.source}</span>
    ),
  },
  {
    header: "Type",
    accessor: (r) => (
      <span className="font-mono text-cyan-dim">{r.event_type}</span>
    ),
    sortValue: (r) => r.event_type,
  },
  {
    header: "Severity",
    accessor: (r) => <SeverityBadge value={r.severity} />,
    sortValue: (r) => SEVERITY_RANK[r.severity] ?? -1,
  },
  {
    header: "Source IP",
    accessor: (r) => (
      <span className="font-mono text-cyan-glow/50">{r.src_ip ?? "-"}</span>
    ),
    sortValue: (r) => r.src_ip ?? "",
  },
  {
    header: "User",
    accessor: (r) => (
      <span className="text-gray-400">{r.username ?? "-"}</span>
    ),
  },
  {
    header: "Message",
    accessor: (r) => (
      <span className="block max-w-xs truncate text-gray-500" title={r.message ?? ""}>
        {r.message ?? "-"}
      </span>
    ),
  },
];
