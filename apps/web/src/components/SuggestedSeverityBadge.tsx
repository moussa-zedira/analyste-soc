"use client";

const COLORS: Record<string, string> = {
  low: "text-green-400 border-green-600",
  medium: "text-yellow-400 border-yellow-600",
  high: "text-orange-400 border-orange-600",
  critical: "text-red-400 border-red-600",
};

export function SuggestedSeverityBadge({
  actual,
  suggested,
}: {
  actual: string;
  suggested: string | null;
}) {
  if (!suggested || suggested === actual) return null;

  const color = COLORS[suggested] ?? "text-gray-400 border-gray-600";

  return (
    <span
      className={`inline-flex items-center gap-1 rounded border border-dashed px-2 py-0.5 text-xs font-medium ${color}`}
      title={`AI suggests severity: ${suggested}`}
    >
      <span className="text-[10px] opacity-70">AI:</span>
      {suggested.toUpperCase()}
    </span>
  );
}
