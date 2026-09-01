import type { IncidentDetail, IncidentStatus } from "../actions";

const URGENCY: Record<string, string> = {
  critical: "Immediate action required.",
  high: "Prompt investigation recommended.",
  medium: "Review at your earliest convenience.",
  low: "Informational — monitor for changes.",
};

const STATUS_ADVICE: Record<IncidentStatus, string> = {
  new: "This incident has not been reviewed yet.",
  investigating: "This incident is currently being investigated.",
  resolved: "This incident has been resolved.",
  false_positive: "This incident was dismissed as a false positive.",
};

function describePhases(phases: string[]): string {
  const set = new Set(phases);
  const parts: string[] = [];

  if (set.has("reconnaissance"))
    parts.push("scanned the network for vulnerabilities");
  if (set.has("delivery")) parts.push("delivered malicious payloads");
  if (set.has("exploitation"))
    parts.push("exploited vulnerabilities to gain access");
  if (set.has("persistence"))
    parts.push("installed backdoors to maintain access");
  if (set.has("command_and_control"))
    parts.push("established remote control over the system");

  if (parts.length === 0) return "performed unclassified activity";
  if (parts.length === 1) return parts[0];
  return parts.slice(0, -1).join(", ") + ", and " + parts[parts.length - 1];
}

export function ExecutiveSummary({
  incident,
}: {
  incident: IncidentDetail;
}) {
  const phaseDesc = describePhases(incident.phasesDetected);

  return (
    <div className="flex flex-col gap-2">
      <div
        className="rounded-md border-l-[3px] py-2 pl-3 pr-2"
        style={{
          borderColor:
            incident.severity === "critical"
              ? "#ef4444"
              : incident.severity === "high"
                ? "#c55f5f"
                : incident.severity === "medium"
                  ? "#a88940"
                  : "#6fbf73",
          background:
            incident.severity === "critical" || incident.severity === "high"
              ? "#1c1010"
              : "transparent",
        }}
      >
        <p className="text-[12px] font-semibold leading-[18px] text-ink">
          {URGENCY[incident.severity] ?? "Review this incident."}
        </p>
        <p className="mt-1 text-[11px] leading-[17px] text-muted">
          An attacker at{" "}
          <span className="font-mono font-semibold text-ink">
            {incident.attackerIp}
          </span>{" "}
          targeted your system at{" "}
          <span className="font-mono font-semibold text-ink">
            {incident.victimIp}
          </span>
          . The attacker {phaseDesc}.
          {" "}{incident.phaseCount} of 5 attack stages were detected across{" "}
          {incident.eventCount.toLocaleString()} events.
        </p>
        <p className="mt-1.5 text-[10px] text-subtle">
          {STATUS_ADVICE[incident.status]}
        </p>
      </div>
    </div>
  );
}
