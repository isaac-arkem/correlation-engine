import { Caption } from "@/components/ui/caption";
import { Card, CardHeader, CardBody } from "@/components/ui/card";
import { formatNumber } from "@/lib/utils/format";
import { sourceLabel, phaseLabel } from "@/lib/utils/phases";
import type { OverviewStats } from "../actions";
import { PhaseBarChart } from "./phase-bar-chart";
import { SourceDonutChart } from "./source-donut-chart";

const SEVERITY_TONE: Record<string, string> = {
  critical: "#d68080",
  high: "#c55f5f",
  medium: "#a88940",
  low: "#6fbf73",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

function buildHealthSummary(stats: OverviewStats): string {
  const sources = Object.keys(stats.bySource);
  const phases = Object.keys(stats.byPhase);

  if (stats.totalEvents === 0) {
    return "No events ingested yet. Run the correlation engine to import log data.";
  }

  const parts: string[] = [];
  parts.push(
    `${formatNumber(stats.totalEvents)} events collected from ${sources.length} source${sources.length !== 1 ? "s" : ""} (${sources.map((s) => sourceLabel(s)).join(", ")}).`
  );

  if (stats.incidentCount > 0) {
    parts.push(
      `${stats.incidentCount} incident${stats.incidentCount !== 1 ? "s" : ""} detected across ${phases.length} attack phase${phases.length !== 1 ? "s" : ""}.`
    );
  } else {
    parts.push("No incidents detected.");
  }

  if (stats.unreviewedCritical > 0) {
    parts.push(
      `${stats.unreviewedCritical} critical/high incident${stats.unreviewedCritical !== 1 ? "s" : ""} still need review.`
    );
  }

  return parts.join(" ");
}

export function OverviewCards({ stats }: { stats: OverviewStats }) {
  const sourceCount = Object.values(stats.bySource).filter((v) => v > 0).length;
  const severities = SEVERITY_ORDER.filter(
    (s) => (stats.bySeverity[s] ?? 0) > 0
  );
  // Also include any severity not in the standard list
  for (const s of Object.keys(stats.bySeverity)) {
    if (!SEVERITY_ORDER.includes(s)) severities.push(s);
  }
  // Fall back to standard list if no incidents at all
  const sevDisplay = severities.length > 0 ? severities : SEVERITY_ORDER;

  return (
    <div className="grid min-h-0 grid-cols-2 gap-1.5">
      {/* Alert banner */}
      {stats.unreviewedCritical > 0 && (
        <div className="col-span-2 flex items-center gap-2 rounded-md border border-red-900/60 bg-red-950/40 px-3 py-2">
          <span className="h-2 w-2 shrink-0 rounded-full bg-red-500" />
          <span className="text-[11px] font-semibold text-red-300">
            {stats.unreviewedCritical} unreviewed critical/high incident{stats.unreviewedCritical !== 1 ? "s" : ""} — action needed
          </span>
        </div>
      )}

      {/* System health summary */}
      <Card className="col-span-2 px-2.5 py-2">
        <span className="text-[11px] font-medium text-ink">
          System health
        </span>
        <p className="mt-1 text-[11px] leading-[16px] text-muted">
          {buildHealthSummary(stats)}
        </p>
      </Card>

      <StatTile
        className="col-span-2"
        label="Raw events"
        sub={`${formatNumber(stats.classifiedEvents)} classified`}
        value={formatNumber(stats.totalEvents)}
        tone="#e5e5e5"
      />
      <StatTile
        label="Incidents"
        sub="correlated"
        value={String(stats.incidentCount)}
        tone="#e0dd5b"
      />
      <StatTile
        label="Sources"
        sub={Object.entries(stats.bySource)
          .filter(([, v]) => v > 0)
          .map(([k]) => sourceLabel(k))
          .join(" · ")}
        value={String(sourceCount)}
        tone="#60a5fa"
      />
      <Card className="col-span-2 px-2.5 py-2">
        <span className="truncate text-[11px] font-medium text-ink">
          Severity
        </span>
        <Caption className="mt-0.5 truncate">open incidents</Caption>
        <div className="mt-2 flex flex-col gap-1">
          {sevDisplay.map((sev) => (
            <div key={sev} className="flex items-center justify-between">
              <span className="font-mono text-[10px] uppercase text-muted">
                {sev}
              </span>
              <span
                className="font-mono text-[11px] font-semibold"
                style={{ color: SEVERITY_TONE[sev] ?? "#a3a3a3" }}
              >
                {stats.bySeverity[sev] ?? 0}
              </span>
            </div>
          ))}
        </div>
      </Card>
      <Card className="col-span-2">
        <CardHeader title="Events by phase" />
        <CardBody>
          <PhaseBarChart byPhase={stats.byPhase} />
        </CardBody>
      </Card>
      <Card className="col-span-2">
        <CardHeader title="Sources" />
        <CardBody>
          <SourceDonutChart bySource={stats.bySource} />
        </CardBody>
      </Card>
    </div>
  );
}

function StatTile({
  label,
  sub,
  value,
  tone,
  className,
}: {
  label: string;
  sub: string;
  value: string;
  tone: string;
  className?: string;
}) {
  return (
    <Card className={`px-2.5 py-2 ${className ?? ""}`}>
      <span className="truncate text-[11px] font-medium text-ink">{label}</span>
      <Caption className="mt-0.5 truncate">{sub}</Caption>
      <p
        className="mt-3 text-right text-[22px] font-semibold leading-none tabular-nums"
        style={{ color: tone }}
      >
        {value}
      </p>
    </Card>
  );
}
