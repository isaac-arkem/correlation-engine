"use client";

const KNOWN_COLORS: Record<string, string> = {
  suricata: "#60a5fa",
  windows_security: "#a88940",
  powershell: "#6fbf73",
};

const FALLBACK_COLORS = [
  "#f472b6", "#818cf8", "#34d399", "#fb923c", "#a78bfa",
  "#38bdf8", "#facc15", "#f87171",
];

function sourceColor(source: string, index: number): string {
  return KNOWN_COLORS[source] ?? FALLBACK_COLORS[index % FALLBACK_COLORS.length];
}

import { sourceLabel } from "@/lib/utils/phases";

export function SourceDonutChart({
  bySource,
}: {
  bySource: Record<string, number>;
}) {
  const entries = Object.entries(bySource).filter(([, v]) => v > 0);
  const total = entries.reduce((sum, [, v]) => sum + v, 0);

  if (entries.length === 0) {
    return (
      <p className="py-6 text-center text-[11px] text-subtle">
        No source data.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {/* Stacked horizontal bar — all slices visible */}
      <div className="flex h-5 w-full overflow-hidden rounded-md">
        {entries.map(([source, count], i) => {
          const pct = (count / total) * 100;
          const minWidth = pct < 3 ? 3 : pct;
          return (
            <div
              key={source}
              className="relative"
              style={{
                width: `${minWidth}%`,
                minWidth: 20,
                background: sourceColor(source, i),
              }}
              title={`${sourceLabel(source)}: ${count.toLocaleString()} (${pct.toFixed(1)}%)`}
            />
          );
        })}
      </div>

      {/* Legend with counts and percentages */}
      <div className="flex flex-col gap-1.5">
        {entries.map(([source, count], i) => {
          const pct = ((count / total) * 100).toFixed(1);
          return (
            <div key={source} className="flex items-start gap-2">
              <span
                className="mt-1 h-2.5 w-2.5 shrink-0 rounded-sm"
                style={{ background: sourceColor(source, i) }}
              />
              <div className="flex flex-1 flex-col">
                <div className="flex items-baseline gap-2">
                  <span className="text-[11px] font-medium text-ink">
                    {sourceLabel(source)}
                  </span>
                  <span className="font-mono text-[10px] font-semibold text-ink">
                    {count.toLocaleString()}
                  </span>
                  <span className="font-mono text-[10px] text-subtle">
                    {pct}%
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="text-[10px] text-subtle">
        Total: <span className="font-mono font-semibold text-muted">{total.toLocaleString()}</span> events across {entries.length} sources
      </div>
    </div>
  );
}
