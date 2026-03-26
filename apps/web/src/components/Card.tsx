export function Card({
  title,
  value,
  subtitle,
  accent,
  loading,
  trend,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  accent?: string;
  loading?: boolean;
  trend?: "up" | "down" | "neutral";
}) {
  if (loading) {
    return (
      <div className="glass-panel hud-corners p-5">
        <div className="skeleton h-4 w-24" />
        <div className="skeleton mt-3 h-9 w-20" />
        <div className="skeleton mt-2 h-3 w-40" />
      </div>
    );
  }

  return (
    <div className="glass-panel hud-corners group relative p-5 transition-all duration-300 hover:shadow-cyan-md">
      {/* Scan line on hover */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden rounded-lg opacity-0 transition-opacity duration-500 group-hover:opacity-100">
        <div className="absolute top-0 left-0 right-0 h-px animate-scan-line bg-cyan-glow-line" />
      </div>

      <div className="relative">
        <p className="hud-label">{title}</p>
        <div className="mt-2 flex items-baseline gap-2">
          <p
            className={`text-3xl font-bold tracking-tight ${
              accent ?? "glow-text"
            }`}
            style={
              !accent
                ? undefined
                : {
                    textShadow: "0 0 8px rgba(0, 229, 255, 0.3)",
                  }
            }
          >
            {value}
          </p>
          {trend && trend !== "neutral" && (
            <span
              className={`flex items-center text-xs font-semibold ${
                trend === "up" ? "text-red-400" : "text-green-400"
              }`}
            >
              <svg
                className={`h-3.5 w-3.5 ${trend === "down" ? "rotate-180" : ""}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2.5}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M4.5 15.75l7.5-7.5 7.5 7.5"
                />
              </svg>
            </span>
          )}
        </div>
        {subtitle && (
          <p className="mt-1.5 text-[11px] tracking-wide text-gray-500">
            {subtitle}
          </p>
        )}
      </div>
    </div>
  );
}
