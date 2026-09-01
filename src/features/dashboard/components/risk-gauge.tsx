"use client";

const ZONES = [
  { label: "Low", max: 30, color: "#6fbf73", bg: "#16261a" },
  { label: "Medium", max: 50, color: "#a88940", bg: "#2a2113" },
  { label: "High", max: 70, color: "#c55f5f", bg: "#2c1414" },
  { label: "Critical", max: 100, color: "#ef4444", bg: "#3b1111" },
];

function getZone(score: number) {
  return ZONES.find((z) => score <= z.max) ?? ZONES[ZONES.length - 1];
}

export function RiskGauge({ score }: { score: number }) {
  const zone = getZone(score);
  const pct = Math.min(score, 100);

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-baseline justify-between">
        <span className="text-[11px] font-medium text-muted">Risk Score</span>
        <div className="flex items-baseline gap-1.5">
          <span
            className="font-mono text-[20px] font-bold leading-none"
            style={{ color: zone.color }}
          >
            {score}
          </span>
          <span className="text-[10px] text-subtle">/ 100</span>
        </div>
      </div>

      {/* Track */}
      <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-neutral-800">
        {/* Zone segments */}
        {ZONES.map((z, i) => {
          const prevMax = i === 0 ? 0 : ZONES[i - 1].max;
          return (
            <div
              key={z.label}
              className="absolute top-0 h-full"
              style={{
                left: `${prevMax}%`,
                width: `${z.max - prevMax}%`,
                background: z.bg,
              }}
            />
          );
        })}
        {/* Fill */}
        <div
          className="absolute left-0 top-0 h-full rounded-full transition-all"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, #6fbf73 0%, ${zone.color} 100%)`,
          }}
        />
        {/* Needle */}
        <div
          className="absolute top-0 h-full w-0.5 bg-white"
          style={{ left: `${pct}%`, transform: "translateX(-50%)" }}
        />
      </div>

      {/* Zone labels */}
      <div className="flex">
        {ZONES.map((z, i) => {
          const prevMax = i === 0 ? 0 : ZONES[i - 1].max;
          const isActive = score > prevMax && score <= z.max;
          return (
            <span
              key={z.label}
              className="text-center text-[9px]"
              style={{
                width: `${z.max - prevMax}%`,
                color: isActive ? z.color : "#555",
                fontWeight: isActive ? 700 : 400,
              }}
            >
              {z.label}
            </span>
          );
        })}
      </div>
    </div>
  );
}
