"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Caption } from "@/components/ui/caption";
import { cn } from "@/lib/utils/cn";
import { formatNumber } from "@/lib/utils/format";
import { phaseShortLabel } from "@/lib/utils/phases";
import type { EvaluationData } from "../actions";

function computeMetrics(tp: number, fp: number, fn: number) {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 =
    precision + recall > 0
      ? (2 * precision * recall) / (precision + recall)
      : 0;
  return { precision, recall, f1 };
}

const RESULT_LABEL: Record<
  EvaluationData["incidents"][number]["result"],
  { label: string; color: string }
> = {
  reconstructed: { label: "Reconstructed", color: "#6fbf73" },
  extra: { label: "Extra incident", color: "#a88940" },
  false_positive: { label: "False positive", color: "#c55f5f" },
  unreviewed: { label: "Unreviewed", color: "#60a5fa" },
};

export function MetricsPanel({ data }: { data: EvaluationData }) {
  const [fpCount, setFpCount] = useState(data.falsePositives);
  const [fnCount, setFnCount] = useState(data.falseNegatives);

  useEffect(() => {
    setFpCount(data.falsePositives);
    setFnCount(data.falseNegatives);
  }, [data.falsePositives, data.falseNegatives, data.runId]);

  const { precision, recall, f1 } = computeMetrics(
    data.truePositives,
    fpCount,
    fnCount,
  );

  return (
    <div className="flex flex-col gap-3">
      <Card>
        <CardBody className="p-3">
          <p className="text-[12px] leading-[18px] text-muted">
            This page measures the correlation engine, not Elasticsearch.
            A campaign is only counted if classified events between a pair
            span two or more kill-chain phases — the same rule the engine
            uses. Crossing every auto-detected IP is not ground truth.
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Alert reduction" />
        <CardBody className="p-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_auto_1fr_auto_1fr] sm:items-center">
            <ReductionStat
              label="Classified events"
              value={formatNumber(data.classifiedEvents)}
              hint="phase-tagged events in this run"
            />
            <Arrow />
            <ReductionStat
              label="Incidents"
              value={formatNumber(data.totalIncidents)}
              hint="multi-stage campaigns (≥2 phases)"
            />
            <Arrow />
            <ReductionStat
              label="Reduction"
              value={
                data.totalIncidents > 0
                  ? `${formatNumber(data.reduction)}:1`
                  : "—"
              }
              hint="events per incident"
              accent
            />
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Campaign reconstruction">
          <span className="font-mono text-[10px] text-subtle">
            {data.campaigns.length > 0
              ? `${data.reconstructed}/${data.campaigns.length} multi-stage pairs`
              : "no multi-stage pairs"}
          </span>
        </CardHeader>
        <CardBody className="p-0">
          {data.campaigns.length === 0 ? (
            <p className="px-3 py-4 text-[11px] leading-[17px] text-muted">
              No attacker→victim pair in this run has two or more kill-chain
              phases. Single-phase noise is suppressed by design
              {data.suppressed > 0
                ? ` (${data.suppressed} pair${data.suppressed === 1 ? "" : "s"}).`
                : "."}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-[11px]">
                <thead>
                  <tr className="border-b border-line text-left text-[10px] uppercase tracking-wider text-subtle">
                    <th className="px-3 py-2 font-medium">Multi-stage pair</th>
                    <th className="px-3 py-2 font-medium">Reconstructed</th>
                    <th className="px-3 py-2 font-medium">Phases</th>
                    <th className="px-3 py-2 font-medium">Events</th>
                  </tr>
                </thead>
                <tbody>
                  {data.campaigns.map((c) => (
                    <tr
                      key={`${c.attackerIp}-${c.victimIp}`}
                      className="border-b border-line/50"
                    >
                      <td className="px-3 py-2 font-mono text-ink">
                        {c.incidentId ? (
                          <Link
                            href={`/incidents/${c.incidentId}`}
                            className="hover:text-highlight"
                          >
                            {c.attackerIp} → {c.victimIp}
                          </Link>
                        ) : (
                          `${c.attackerIp} → ${c.victimIp}`
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className="font-semibold"
                          style={{ color: c.found ? "#6fbf73" : "#c55f5f" }}
                        >
                          {c.found ? "Yes" : "Missed"}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-muted">
                        {c.found
                          ? `${c.phaseCount}/5 · ${c.phasesDetected.map(phaseShortLabel).join(" → ")}`
                          : "—"}
                      </td>
                      <td className="px-3 py-2 font-mono text-muted">
                        {c.found ? formatNumber(c.eventCount) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="grid grid-cols-2 gap-px border-t border-line sm:grid-cols-4">
            <MiniStat
              label="Reconstructed"
              value={data.reconstructed}
              color="#6fbf73"
            />
            <MiniStat label="Missed" value={data.missed} color="#c55f5f" />
            <MiniStat
              label="Extra incidents"
              value={data.extra}
              color="#a88940"
            />
            <MiniStat
              label="Single-phase (not incidents)"
              value={data.suppressed}
              color="#838383"
            />
          </div>
        </CardBody>
      </Card>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <ScoreCard
          label="Precision"
          value={precision}
          description="TP / (TP + FP)"
        />
        <ScoreCard
          label="Recall"
          value={recall}
          description="TP / (TP + FN)"
        />
        <ScoreCard
          label="F1 Score"
          value={f1}
          description="2 × P × R / (P + R)"
        />
      </div>

      <Card>
        <CardHeader title="How the scores are counted" />
        <CardBody className="p-3">
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <CountBlock
              label="True positives"
              hint="multi-stage pairs that became incidents"
              value={data.truePositives}
              color="#6fbf73"
              locked
            />
            <CountBlock
              label="False positives"
              hint="incidents that were not a multi-stage pair — raise if a reconstruction was wrong"
              value={fpCount}
              color="#c55f5f"
              onChange={setFpCount}
            />
            <CountBlock
              label="False negatives"
              hint="pairs with ≥2 phases but no incident — raise if you ran an attack the engine missed"
              value={fnCount}
              color="#a88940"
              onChange={setFnCount}
            />
          </div>
          {data.unreviewed > 0 && !data.hasGroundTruth ? (
            <p className="mt-3 text-[11px] text-blue-300">
              {data.unreviewed} incident
              {data.unreviewed !== 1 ? "s" : ""} still unreviewed. Mark
              resolved or false positive on the incident page before treating
              precision as final.
            </p>
          ) : null}
          <p className="mt-3 text-[11px] leading-[17px] text-subtle">
            True negatives are not reported. The engine only emits incidents;
            it does not classify “non-attacks,” so a full confusion matrix
            would overstate the evaluation.
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Incidents in this run">
          <span className="font-mono text-[10px] text-subtle">
            {data.totalIncidents} total
          </span>
        </CardHeader>
        <CardBody className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="border-b border-line text-left text-[10px] uppercase tracking-wider text-subtle">
                  <th className="px-3 py-2 font-medium">Attacker → Victim</th>
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">Phases</th>
                  <th className="px-3 py-2 font-medium">Events</th>
                  <th className="px-3 py-2 font-medium">Result</th>
                </tr>
              </thead>
              <tbody>
                {data.incidents.map((inc) => {
                  const info = RESULT_LABEL[inc.result];
                  return (
                    <tr
                      key={inc.id}
                      className="border-b border-line/50 hover:bg-hover"
                    >
                      <td className="px-3 py-2 font-mono text-ink">
                        <Link
                          href={`/incidents/${inc.id}`}
                          className="hover:text-highlight"
                        >
                          {inc.attackerIp} → {inc.victimIp}
                        </Link>
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={cn(
                            "inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase",
                            inc.severity === "critical" &&
                              "bg-red-500/15 text-red-400",
                            inc.severity === "high" &&
                              "bg-red-500/10 text-red-300",
                            inc.severity === "medium" &&
                              "bg-yellow-500/10 text-yellow-400",
                            inc.severity === "low" &&
                              "bg-green-500/10 text-green-400",
                          )}
                        >
                          {inc.severity}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-muted">
                        {inc.phasesDetected.length}/5
                      </td>
                      <td className="px-3 py-2 font-mono text-muted">
                        {formatNumber(inc.eventCount)}
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className="font-semibold"
                          style={{ color: info.color }}
                        >
                          {info.label}
                        </span>
                      </td>
                    </tr>
                  );
                })}
                {data.incidents.length === 0 ? (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-3 py-6 text-center text-subtle"
                    >
                      No incidents in this dataset.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

function Arrow() {
  return (
    <span
      className="hidden text-center text-[16px] text-subtle sm:block"
      aria-hidden="true"
    >
      →
    </span>
  );
}

function ReductionStat({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: string;
  hint: string;
  accent?: boolean;
}) {
  return (
    <div className="rounded-md border border-line bg-base px-3 py-3">
      <Caption>{label}</Caption>
      <p
        className={cn(
          "mt-1.5 font-mono text-[22px] font-semibold tabular-nums leading-none",
          accent ? "text-accent" : "text-highlight",
        )}
      >
        {value}
      </p>
      <p className="mt-1.5 text-[10px] text-subtle">{hint}</p>
    </div>
  );
}

function MiniStat({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="px-3 py-2.5">
      <Caption>{label}</Caption>
      <p
        className="mt-1 font-mono text-[18px] font-semibold tabular-nums"
        style={{ color }}
      >
        {value}
      </p>
    </div>
  );
}

function CountBlock({
  label,
  hint,
  value,
  color,
  locked,
  onChange,
}: {
  label: string;
  hint: string;
  value: number;
  color: string;
  locked?: boolean;
  onChange?: (n: number) => void;
}) {
  return (
    <div className="rounded-md border border-line bg-base px-2.5 py-2">
      <span className="text-[11px] font-medium text-ink">{label}</span>
      <p className="mt-0.5 text-[10px] leading-[14px] text-subtle">{hint}</p>
      {locked || !onChange ? (
        <p
          className="mt-3 text-right font-mono text-[22px] font-semibold tabular-nums leading-none"
          style={{ color }}
        >
          {value}
        </p>
      ) : (
        <input
          type="number"
          min={0}
          value={value}
          onChange={(e) =>
            onChange(Math.max(0, parseInt(e.target.value, 10) || 0))
          }
          className="mt-3 w-full rounded-md border border-line bg-field px-2 py-1 text-right font-mono text-[22px] font-semibold tabular-nums outline-none focus:border-line-strong"
          style={{ color }}
        />
      )}
    </div>
  );
}

function ScoreCard({
  label,
  value,
  description,
}: {
  label: string;
  value: number;
  description: string;
}) {
  const pct = (value * 100).toFixed(1);
  const color =
    value >= 0.8
      ? "#6fbf73"
      : value >= 0.5
        ? "#a88940"
        : value > 0
          ? "#c55f5f"
          : "#737373";

  return (
    <Card className="px-2.5 py-2">
      <span className="text-[11px] font-medium text-ink">{label}</span>
      <p className="mt-0.5 font-mono text-[10px] text-subtle">{description}</p>
      <p
        className="mt-3 text-right text-[22px] font-semibold leading-none tabular-nums"
        style={{ color }}
      >
        {pct}%
      </p>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-base">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${Math.min(100, value * 100)}%`,
            backgroundColor: color,
          }}
        />
      </div>
    </Card>
  );
}
