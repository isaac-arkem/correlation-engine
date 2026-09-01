"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  phaseShortLabel as phaseLabel,
  phaseColor as getPhaseColor,
} from "@/lib/utils/phases";

function phaseColor(phase: string, _index: number): string {
  return getPhaseColor(phase);
}

export function PhaseBarChart({
  byPhase,
}: {
  byPhase: Record<string, number>;
}) {
  // Find the dominant phase (if any is 100x+ larger than next, exclude it for scale)
  const sorted = Object.entries(byPhase).sort((a, b) => b[1] - a[1]);
  const dominant =
    sorted.length >= 2 && sorted[0][1] > sorted[1][1] * 50
      ? sorted[0]
      : null;

  const data = Object.entries(byPhase)
    .filter(([phase]) => !dominant || phase !== dominant[0])
    .filter(([, count]) => count > 0)
    .map(([phase, count]) => ({
      phase,
      label: phaseLabel(phase),
      count,
    }));

  if (data.length === 0 && !dominant) {
    return (
      <p className="py-6 text-center text-[11px] text-subtle">
        No phase data.
      </p>
    );
  }

  return (
    <div>
      {dominant && (
        <div className="mb-2 flex items-center gap-2">
          <span
            className="h-2 w-2 rounded-full"
            style={{ background: getPhaseColor(dominant[0]) }}
          />
          <span className="text-[10px] text-muted">
            {phaseLabel(dominant[0])}:{" "}
            <span className="font-mono font-semibold text-ink">
              {dominant[1].toLocaleString()}
            </span>{" "}
            events (excluded from chart for scale)
          </span>
        </div>
      )}
      {data.length > 0 ? (
        <ResponsiveContainer width="100%" height={160}>
          <BarChart
            data={data}
            margin={{ top: 4, right: 4, bottom: 0, left: -20 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#333"
              vertical={false}
            />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 10, fill: "#a3a3a3" }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 10, fill: "#a3a3a3" }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v: number) =>
                v >= 1000 ? `${(v / 1000).toFixed(0)}k` : String(v)
              }
            />
            <Tooltip
              contentStyle={{
                background: "#1a1a1a",
                border: "1px solid #333",
                borderRadius: 6,
                fontSize: 11,
              }}
              labelStyle={{ color: "#a3a3a3" }}
              itemStyle={{ color: "#e5e5e5" }}
              formatter={(value) => [
                Number(value).toLocaleString(),
                "Events",
              ]}
            />
            <Bar dataKey="count" radius={[3, 3, 0, 0]}>
              {data.map((d, i) => (
                <Cell
                  key={d.phase}
                  fill={phaseColor(d.phase, i)}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : null}
    </div>
  );
}
