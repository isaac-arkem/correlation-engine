import { Suspense } from "react";

import { ContextTile, TopBar } from "@/components/ui/top-bar";
import { getCorrelationRuns, getLatestRunId } from "@/features/dashboard/actions";
import { RunSelector } from "@/features/dashboard/components/run-selector";
import { getEvaluationData } from "@/features/evaluation/actions";
import { MetricsPanel } from "@/features/evaluation/components/metrics-panel";

export default async function EvaluationPage({
  searchParams,
}: {
  searchParams: Promise<{ run?: string }>;
}) {
  const { run: runParam } = await searchParams;
  const [runs, latestRunId] = await Promise.all([
    getCorrelationRuns(),
    runParam ? Promise.resolve(runParam) : getLatestRunId(),
  ]);
  const activeRunId = runParam ?? latestRunId;

  if (!activeRunId) {
    return (
      <>
        <TopBar>
          <ContextTile kicker="results" title="Evaluation" />
        </TopBar>
        <main className="flex flex-1 items-center justify-center p-6">
          <p className="text-[12px] text-muted">
            No correlation runs yet. Go to{" "}
            <a href="/correlate" className="text-ink underline">Correlate</a>{" "}
            to upload your first dataset.
          </p>
        </main>
      </>
    );
  }

  const data = await getEvaluationData(activeRunId);

  return (
    <>
      <TopBar>
        <ContextTile kicker="results" title="Evaluation" />
        <Suspense>
          <RunSelector runs={runs} activeRunId={activeRunId} />
        </Suspense>
      </TopBar>

      <main className="flex min-h-0 flex-1 flex-col gap-3 overflow-auto p-3">
        {data ? (
          <MetricsPanel data={data} />
        ) : (
          <p className="text-[12px] text-muted">Run not found.</p>
        )}
      </main>
    </>
  );
}
