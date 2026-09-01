import Link from "next/link";
import { notFound } from "next/navigation";

import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { CountBadge } from "@/components/ui/count-badge";
import { StatusPill } from "@/components/ui/status-pill";
import { Tag } from "@/components/ui/tag";
import { ContextTile, TopBar } from "@/components/ui/top-bar";
import { severityTone } from "@/components/ui/tone";
import { getIncidentById } from "@/features/dashboard/actions";
import { toQueryString } from "@/features/dashboard/lib/window";
import { AttackTimelineChart } from "@/features/dashboard/components/attack-timeline-chart";
import { EventTable } from "@/features/dashboard/components/event-table";
import { ExecutiveSummary } from "@/features/dashboard/components/executive-summary";
import { KillChainTimeline } from "@/features/dashboard/components/kill-chain-bar";
import { RecommendedActions } from "@/features/dashboard/components/recommended-actions";
import { RiskGauge } from "@/features/dashboard/components/risk-gauge";
import { StatusSelector } from "@/features/dashboard/components/status-selector";
import { ExportPdfButton } from "@/features/dashboard/components/export-pdf-button";
import { AiAssistant } from "@/features/dashboard/components/ai-assistant";
import { formatDate, formatNumber } from "@/lib/utils/format";
import { getSessionUser } from "@/features/auth/lib/session";

export default async function IncidentDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ from?: string; to?: string; window?: string; run?: string }>;
}) {
  const { id } = await params;
  const range = await searchParams;
  const [incident, user] = await Promise.all([
    getIncidentById(id),
    getSessionUser(),
  ]);

  if (!incident) return notFound();

  return (
    <>
      <TopBar>
        <Link
          href={`/${toQueryString(range)}`}
          className="text-[11px] text-muted hover:text-ink"
        >
          ← Insights
        </Link>
        <ContextTile
          kicker={incident.severity}
          title={`${incident.attackerIp} → ${incident.victimIp}`}
        />
        <StatusPill
          tone={severityTone(incident.severity)}
          label={incident.severity}
        />
        <StatusSelector
          incidentId={incident.id}
          currentStatus={incident.status}
          userEmail={user?.email ?? undefined}
        />
        <div className="flex flex-wrap items-center gap-1.5">
          <Tag>{formatNumber(incident.eventCount)} events</Tag>
          <Tag>{incident.phaseCount} phases</Tag>
          <Tag>
            {formatDate(incident.firstSeen)} – {formatDate(incident.lastSeen)}
          </Tag>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <ExportPdfButton incidentId={incident.id} />
        </div>
      </TopBar>

      <main className="flex min-h-0 flex-1 flex-col gap-2 overflow-auto p-3 lg:flex-row lg:overflow-hidden">
        <section className="grid h-[34rem] min-h-0 shrink-0 grid-rows-[8.5rem_5.75rem_minmax(0,1fr)_minmax(0,1.2fr)] gap-2 overflow-hidden lg:h-full lg:w-[18.5rem]">
          <Card>
            <CardHeader title="What happened" />
            <CardBody className="p-3">
              <ExecutiveSummary incident={incident} />
            </CardBody>
          </Card>

          <Card>
            <CardBody className="p-3">
              <RiskGauge score={incident.riskScore} />
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Recommended actions" />
            <CardBody>
              <RecommendedActions status={incident.status} />
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Kill chain">
              <CountBadge>{incident.phaseCount}/5</CountBadge>
            </CardHeader>
            <CardBody>
              <KillChainTimeline
                detected={incident.phasesDetected}
                breakdown={incident.phaseBreakdown}
              />
            </CardBody>
          </Card>
        </section>

        <section className="grid min-h-0 flex-1 grid-rows-[14rem_minmax(0,1fr)] gap-2 overflow-hidden">
          <Card>
            <CardHeader title="Attack timeline" />
            <CardBody>
              <AttackTimelineChart events={incident.events} />
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Linked events">
              <CountBadge>{formatNumber(incident.events.length)}</CountBadge>
            </CardHeader>
            <CardBody>
              <EventTable
                events={incident.events}
                totalCount={incident.eventCount}
                phaseBreakdown={incident.phaseBreakdown}
              />
            </CardBody>
          </Card>
        </section>
      </main>

      <AiAssistant incident={incident} />
    </>
  );
}
