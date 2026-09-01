"use client";

import { useCallback, useState, useTransition } from "react";

import type { IncidentDetail, EventRow } from "../actions";
import { getIncidentForReport } from "../actions";
import { phaseLabel, sourceLabel } from "@/lib/utils/phases";

function formatDate(iso: string) {
  return new Date(iso).toLocaleString("en-GB", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function buildReportHtml(
  incident: IncidentDetail,
  nonReconEvents: EventRow[]
) {
  const phaseOrder = [
    "reconnaissance",
    "delivery",
    "exploitation",
    "persistence",
    "command_and_control",
  ];

  const phaseRows = phaseOrder
    .filter((p) => incident.phasesDetected.includes(p))
    .map(
      (p) =>
        `<tr><td style="padding:4px 8px;border:1px solid #ccc">${phaseLabel(p)}</td>
         <td style="padding:4px 8px;border:1px solid #ccc;text-align:right">${incident.phaseBreakdown[p] ?? 0}</td></tr>`
    )
    .join("");

  const topEvents = nonReconEvents.slice(0, 100);
  const eventRows = topEvents
    .map(
      (ev) =>
        `<tr>
          <td style="padding:3px 6px;border:1px solid #ddd;font-size:10px">${formatDate(ev.eventTime)}</td>
          <td style="padding:3px 6px;border:1px solid #ddd;font-size:10px">${sourceLabel(ev.source)}</td>
          <td style="padding:3px 6px;border:1px solid #ddd;font-size:10px">${ev.killChainPhase ? phaseLabel(ev.killChainPhase) : "-"}</td>
          <td style="padding:3px 6px;border:1px solid #ddd;font-size:10px">${ev.srcIp ?? "-"}:${ev.srcPort ?? ""} → ${ev.destIp ?? "-"}:${ev.destPort ?? ""}</td>
          <td style="padding:3px 6px;border:1px solid #ddd;font-size:10px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${ev.signature ?? ev.message ?? "-"}</td>
        </tr>`
    )
    .join("");

  return `<!DOCTYPE html>
<html><head>
<title>Incident Report - ${incident.attackerIp} → ${incident.victimIp}</title>
<style>
  body { font-family: Arial, sans-serif; color: #1a1a1a; max-width: 900px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 18px; margin-bottom: 4px; }
  h2 { font-size: 14px; margin-top: 24px; border-bottom: 1px solid #333; padding-bottom: 4px; }
  .meta { font-size: 11px; color: #666; margin-bottom: 16px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 12px 0; }
  .stat { background: #f5f5f5; padding: 10px; border-radius: 4px; }
  .stat-label { font-size: 10px; text-transform: uppercase; color: #666; }
  .stat-value { font-size: 18px; font-weight: bold; }
  .severity { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
  .severity-critical { background: #fee2e2; color: #991b1b; }
  .severity-high { background: #fef3c7; color: #92400e; }
  .severity-medium { background: #fef3c7; color: #92400e; }
  .severity-low { background: #d1fae5; color: #065f46; }
  table { border-collapse: collapse; width: 100%; margin-top: 8px; }
  th { background: #f3f4f6; padding: 4px 8px; border: 1px solid #ccc; font-size: 10px; text-align: left; }
  p.summary { font-size: 12px; line-height: 1.6; background: #f9fafb; padding: 12px; border-radius: 4px; border-left: 3px solid #333; }
  @media print { body { padding: 0; } }
</style>
</head><body>
<h1>GCTU-SIEM Incident Report</h1>
<p class="meta">Generated ${new Date().toLocaleString("en-GB")} | Incident ${incident.id.slice(0, 8)}</p>

<h2>Overview</h2>
<div class="grid">
  <div class="stat">
    <div class="stat-label">Attacker</div>
    <div class="stat-value">${incident.attackerIp}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Victim</div>
    <div class="stat-value">${incident.victimIp}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Risk Score</div>
    <div class="stat-value">${incident.riskScore} <span class="severity severity-${incident.severity}">${incident.severity}</span></div>
  </div>
  <div class="stat">
    <div class="stat-label">Status</div>
    <div class="stat-value" style="text-transform:capitalize">${incident.status}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Total Events</div>
    <div class="stat-value">${incident.eventCount.toLocaleString()}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Kill-Chain Phases</div>
    <div class="stat-value">${incident.phaseCount} / 5</div>
  </div>
  <div class="stat">
    <div class="stat-label">First Seen</div>
    <div class="stat-value" style="font-size:14px">${formatDate(incident.firstSeen)}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Last Seen</div>
    <div class="stat-value" style="font-size:14px">${formatDate(incident.lastSeen)}</div>
  </div>
</div>

<h2>Summary</h2>
<p class="summary">${incident.summary}</p>

<h2>Kill-Chain Phase Breakdown</h2>
<table>
  <thead><tr><th>Phase</th><th style="text-align:right">Events</th></tr></thead>
  <tbody>${phaseRows}</tbody>
</table>

<h2>Key Events (Top ${topEvents.length} non-reconnaissance)</h2>
<table>
  <thead><tr><th>Time</th><th>Source</th><th>Phase</th><th>Flow</th><th>Description</th></tr></thead>
  <tbody>${eventRows}</tbody>
</table>
${nonReconEvents.length > 100 ? `<p style="font-size:10px;color:#666;margin-top:4px">${nonReconEvents.length - 100} additional events omitted.</p>` : ""}

<div style="margin-top:32px;padding-top:12px;border-top:1px solid #ccc;font-size:10px;color:#999">
  GCTU-SIEM Correlation Engine &mdash; Report generated automatically
</div>
</body></html>`;
}

export function ExportPdfButton({ incidentId }: { incidentId: string }) {
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  const handleExport = useCallback(() => {
    setError(null);
    startTransition(async () => {
      const data = await getIncidentForReport(incidentId);
      if (!data) {
        setError("Incident not found");
        return;
      }

      const html = buildReportHtml(data.incident, data.allNonReconEvents);
      const win = window.open("", "_blank");
      if (!win) {
        setError("Pop-up blocked");
        return;
      }
      win.document.write(html);
      win.document.close();
      setTimeout(() => win.print(), 400);
    });
  }, [incidentId]);

  return (
    <button
      type="button"
      onClick={handleExport}
      disabled={isPending}
      className="flex items-center gap-1 rounded-md border border-line bg-base px-2 py-1 text-[10px] font-medium text-muted transition-colors hover:border-line-strong hover:text-ink disabled:opacity-50"
    >
      <svg
        className="h-3 w-3"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
      >
        <path d="M4 13h8M8 3v7M5 7l3 3 3-3" />
      </svg>
      {isPending ? "Generating..." : "Export PDF"}
      {error && (
        <span className="ml-1 text-[9px] text-red-400">{error}</span>
      )}
    </button>
  );
}
