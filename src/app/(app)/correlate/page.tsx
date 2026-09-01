import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { ContextTile, TopBar } from "@/components/ui/top-bar";
import { CorrelateTabs } from "@/features/correlate/components/correlate-tabs";

export default function CorrelatePage() {
  return (
    <>
      <TopBar>
        <ContextTile kicker="engine" title="Run Correlation" />
      </TopBar>

      <main className="min-h-0 flex-1 overflow-auto p-3">
        <div className="mx-auto max-w-2xl">
          <Card>
            <CardHeader title="New Correlation Run" />
            <CardBody>
              <p className="mb-6 text-[12px] leading-[19px] text-muted">
                Run the kill-chain correlation engine on uploaded log files or
                live data from your ELK stack. Each run is stored as a separate
                dataset.
              </p>
              <CorrelateTabs />
            </CardBody>
          </Card>
        </div>
      </main>
    </>
  );
}
