import Link from "next/link";

import { Caption } from "@/components/ui/caption";
import { CountBadge } from "@/components/ui/count-badge";
import { StatusPill } from "@/components/ui/status-pill";
import { Tag } from "@/components/ui/tag";
import { severityTone, statusTone } from "@/components/ui/tone";
import { formatDate, formatNumber } from "@/lib/utils/format";
import type { IncidentSummary } from "../actions";
import { KillChainBar } from "./kill-chain-bar";

export function IncidentList({
  incidents,
  query = "",
}: {
  incidents: IncidentSummary[];
  query?: string;
}) {
  if (incidents.length === 0) {
    return (
      <div className="px-3 py-10 text-center text-[12px] text-muted">
        No incidents in this window.
        <Caption className="mt-1">Run ingestion to populate events.</Caption>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-1.5 p-2">
      {incidents.map((inc) => (
        <Link
          key={inc.id}
          href={`/incidents/${inc.id}${query}`}
          className="shrink-0 rounded-md border border-line bg-base px-2.5 py-2 transition-colors hover:border-line-strong"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="truncate font-mono text-[12px] text-ink">
              {inc.attackerIp}{" "}
              <span className="text-subtle">→</span> {inc.victimIp}
            </span>
            <div className="flex items-center gap-1.5">
              <StatusPill
                tone={statusTone(inc.status)}
                label={inc.status}
              />
              <StatusPill
                tone={severityTone(inc.severity)}
                label={inc.severity}
              />
            </div>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <Tag>{formatNumber(inc.eventCount)} events</Tag>
            <Tag>{inc.phaseCount} phases</Tag>
            <Tag>
              {formatDate(inc.firstSeen)} – {formatDate(inc.lastSeen)}
            </Tag>
            <CountBadge>{inc.riskScore}</CountBadge>
          </div>
          <div className="mt-2">
            <KillChainBar detected={inc.phasesDetected} size="sm" />
          </div>
          <p className="mt-1.5 line-clamp-2 text-[11px] text-muted">
            {inc.summary}
          </p>
        </Link>
      ))}
    </div>
  );
}
