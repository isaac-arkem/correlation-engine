import { Suspense } from "react";

import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { CountBadge } from "@/components/ui/count-badge";
import { ContextTile, TopBar } from "@/components/ui/top-bar";
import {
  getCorrelationRuns,
  getIncidents,
  getLatestRunId,
  getOverviewStats,
} from "@/features/dashboard/actions";
import { DateRangePicker } from "@/features/dashboard/components/date-range-picker";
import { IncidentList } from "@/features/dashboard/components/incident-list";
import { LiveMonitor } from "@/features/dashboard/components/live-monitor";
import { OverviewCards } from "@/features/dashboard/components/overview-cards";
import { RunSelector } from "@/features/dashboard/components/run-selector";
import { resolveRange, toQueryString } from "@/features/dashboard/lib/window";
import { AiAssistant } from "@/features/dashboard/components/ai-assistant";
import { formatNumber } from "@/lib/utils/format";

export default async function DashboardPage({
  searchParams,
}: {
  searchParams: Promise<{
    from?: string;
    to?: string;
    window?: string;
    run?: string;
  }>;
}) {
  const { from, to, window: timeWindow, run: runParam } = await searchParams;
  const range = resolveRange(from, to, timeWindow);
  const query = toQueryString({ from, to, window: timeWindow, run: runParam });

  const [runs, latestRunId] = await Promise.all([
    getCorrelationRuns(),
    runParam ? Promise.resolve(runParam) : getLatestRunId(),
  ]);

  const activeRunId = runParam ?? latestRunId;

  if (!activeRunId) {
    return (
      <>
        <TopBar>
          <ContextTile kicker="ops" title="Insights" />
        </TopBar>
        <main className="flex flex-1 items-center justify-center p-6">
          <p className="text-[12px] text-muted">
            No correlation runs yet. Go to{" "}
            <a href="/correlate" className="text-ink underline">
              Correlate
            </a>{" "}
            to upload your first dataset.
          </p>
        </main>
      </>
    );
  }

  return (
    <>
      <TopBar>
        <ContextTile kicker="ops" title="Insights" />
        <div className="flex min-w-0 flex-wrap items-end gap-x-6 gap-y-3">
          <Suspense>
            <RunSelector runs={runs} activeRunId={activeRunId} />
          </Suspense>
          <Suspense>
            <DateRangePicker />
          </Suspense>
        </div>
      </TopBar>

      <main className="flex min-h-0 flex-1 flex-col gap-3 overflow-auto p-3">
        <Suspense>
          <LiveMonitor />
        </Suspense>

        <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:grid-cols-[minmax(28rem,2fr)_minmax(0,3fr)] lg:overflow-hidden">
          <section className="flex min-h-0 min-w-0 flex-col gap-3">
            <Suspense
              fallback={
                <p className="px-3 py-6 text-[11px] text-subtle">Loading overview…</p>
              }
            >
              <OverviewSection runId={activeRunId} from={range.from} to={range.to} />
            </Suspense>
          </section>

          <Card className="min-h-0 flex-1">
            <Suspense
              fallback={
                <CardHeader title="Incidents">
                  <CountBadge>—</CountBadge>
                </CardHeader>
              }
            >
              <IncidentPanel runId={activeRunId} from={range.from} to={range.to} query={query} />
            </Suspense>
          </Card>
        </div>
      </main>

      <Suspense>
        <AiSection runId={activeRunId} from={range.from} to={range.to} />
      </Suspense>
    </>
  );
}

async function OverviewSection({
  runId,
  from,
  to,
}: {
  runId: string;
  from?: string;
  to?: string;
}) {
  const stats = await getOverviewStats(runId, from, to);
  return <OverviewCards stats={stats} />;
}

async function IncidentPanel({
  runId,
  from,
  to,
  query,
}: {
  runId: string;
  from?: string;
  to?: string;
  query: string;
}) {
  const incidents = await getIncidents(runId, from, to);

  return (
    <>
      <CardHeader title="Incidents">
        <CountBadge>{formatNumber(incidents.length)}</CountBadge>
      </CardHeader>
      <CardBody className="p-0">
        <IncidentList incidents={incidents} query={query} />
      </CardBody>
    </>
  );
}

async function AiSection({
  runId,
  from,
  to,
}: {
  runId: string;
  from?: string;
  to?: string;
}) {
  const [stats, incidents] = await Promise.all([
    getOverviewStats(runId, from, to),
    getIncidents(runId, from, to),
  ]);

  return <AiAssistant stats={stats} incidents={incidents} />;
}
