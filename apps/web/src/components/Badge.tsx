"use client";

const SEVERITY_COLORS: Record<string, string> = {
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  open: "bg-red-500/10 text-red-400 border-red-500/30",
  ack: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  closed: "bg-cyan-glow/10 text-cyan-glow border-cyan-glow/30",
};

/** Badge affichant le niveau de severite avec un code couleur. */
export function SeverityBadge({ value }: { value: string }) {
  const cls =
    SEVERITY_COLORS[value.toLowerCase()] ??
    "bg-space-mid text-gray-400 border-gray-700";
  return (
    <span
      className={`inline-block rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${cls}`}
    >
      {value}
    </span>
  );
}

/** Badge affichant le statut d'un incident avec un code couleur. */
export function StatusBadge({ value }: { value: string }) {
  const cls =
    STATUS_COLORS[value.toLowerCase()] ??
    "bg-space-mid text-gray-400 border-gray-700";
  return (
    <span
      className={`inline-block rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${cls}`}
    >
      {value}
    </span>
  );
}
