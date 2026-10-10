"use server";

import { createSupabaseAdminClient } from "@/lib/supabase/server";
import {
  compareToGroundTruth,
  parseGroundTruth,
  samePair,
  type GroundTruth,
} from "@/lib/correlation/ground-truth";
import { normalizePhase, sortPhases } from "@/lib/correlation/phase-vocab";

const EVENT_SCAN_CAP = 15_000;

export interface EvalIncident {
  id: string;
  attackerIp: string;
  victimIp: string;
  severity: string;
  riskScore: number;
  phasesDetected: string[];
  eventCount: number;
  summary: string;
  status: string;
  result: "reconstructed" | "extra" | "false_positive" | "unreviewed";
}

export interface KnownCampaign {
  attackerIp: string;
  victimIp: string;
  found: boolean;
  incidentId: string | null;
  phasesDetected: string[];
  phaseCount: number;
  eventCount: number;
  severity: string | null;
  /** Declared mode only — what the operator asserted was in this campaign. */
  expectedPhases: string[];
  /** Declared but never detected: the classifier's blind spots. */
  missingPhases: string[];
  /** Detected but not declared: over-classification. */
  unexpectedPhases: string[];
  note: string | null;
}

/**
 * How the answer key was obtained.
 *
 * "declared" — campaigns were written down independently of this run
 *   (staged by the operator, or emitted by the synthetic lab generator).
 *   Precision/recall then measure detection accuracy against external truth.
 *
 * "derived" — no ground truth was declared, so the answer key is re-derived
 *   from the events this engine itself classified. This is circular: it can
 *   only measure internal consistency between classification and correlation,
 *   and a campaign the classifier missed entirely is invisible to it rather
 *   than counted as a false negative. Report these figures as a consistency
 *   check, never as detection accuracy.
 */
export type GroundTruthMode = "declared" | "derived";

export interface EvaluationData {
  runId: string;
  runLabel: string;
  groundTruthMode: GroundTruthMode;
  groundTruthLabel: string | null;
  hasGroundTruth: boolean;
  totalEvents: number;
  classifiedEvents: number;
  totalIncidents: number;
  reduction: number;
  reconstructed: number;
  extra: number;
  missed: number;
  suppressed: number;
  /** Declared mode only: campaigns found, but with declared phases missing. */
  partial: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  unreviewed: number;
  campaigns: KnownCampaign[];
  incidents: EvalIncident[];
}

type PairAgg = {
  attackerIp: string;
  victimIp: string;
  phases: Set<string>;
  count: number;
};

function pairKey(a: string, v: string) {
  return `${a}\0${v}`;
}

function directedPair(
  src: string | null,
  dest: string | null,
  attackers: string[],
  victims: string[],
): { attackerIp: string; victimIp: string } | null {
  if (!src || !dest || src === dest) return null;

  const srcA = attackers.includes(src);
  const destV = victims.includes(dest);
  const srcV = victims.includes(src);
  const destA = attackers.includes(dest);

  if ((srcA && destV) || (srcV && destA)) {
    return {
      attackerIp: srcA ? src : dest,
      victimIp: destV ? dest : src,
    };
  }

  if (attackers.length === 0 && victims.length === 0) {
    return { attackerIp: src, victimIp: dest };
  }

  return null;
}

type IncidentRow = {
  id: string;
  attacker_ip: string;
  victim_ip: string;
  severity: string;
  risk_score: number;
  phases_detected: string[] | null;
  event_count: number;
  summary: string;
  status: string | null;
};

function canonicalPhases(phases: string[] | null | undefined): string[] {
  return sortPhases([
    ...new Set(
      (phases ?? [])
        .map((p) => normalizePhase(p))
        .filter((p): p is string => Boolean(p)),
    ),
  ]);
}

export async function getEvaluationData(
  runId: string,
): Promise<EvaluationData | null> {
  const sb = createSupabaseAdminClient();

  const { data: run } = await sb
    .from("correlation_runs")
    .select(
      "id, label, attacker_ips, victim_ips, event_count, source_counts, phase_counts, ground_truth",
    )
    .eq("id", runId)
    .single();

  if (!run) return null;

  const [{ count: storedEvents }, { count: classifiedCount }, { data: incidents }] =
    await Promise.all([
      sb
        .from("events")
        .select("id", { count: "exact", head: true })
        .eq("run_id", runId),
      sb
        .from("events")
        .select("id", { count: "exact", head: true })
        .eq("run_id", runId)
        .not("kill_chain_phase", "is", null),
      sb
        .from("incidents")
        .select(
          "id, attacker_ip, victim_ip, severity, risk_score, phases_detected, event_count, summary, status",
        )
        .eq("run_id", runId)
        // Scoped incidents re-present an engine incident over a sub-window;
        // counting them would score one detection twice.
        .is("scope_from", null)
        .order("risk_score", { ascending: false }),
    ]);

  const rows = (incidents ?? []) as IncidentRow[];
  const attackerIps = (run.attacker_ips ?? []).filter(Boolean);
  const victimIps = (run.victim_ips ?? []).filter(Boolean);
  const classifiedEvents = classifiedCount ?? storedEvents ?? 0;
  const canScanEvents = classifiedEvents <= EVENT_SCAN_CAP;

  // A declared answer key wins over the derived one whenever present.
  let truth: GroundTruth | null = null;
  if (run.ground_truth) {
    try {
      truth = parseGroundTruth(run.ground_truth);
    } catch (err) {
      // A malformed key must not silently degrade to the circular method
      // without the operator knowing, so it is surfaced in the server log.
      console.error(
        `[evaluation] run ${runId} has an unusable ground truth, falling back to derived:`,
        err instanceof Error ? err.message : err,
      );
      truth = null;
    }
  }

  // Re-group classified events by pair. In declared mode this is only used
  // for the suppressed-pair count and per-campaign event totals; it no longer
  // supplies the answer key.
  const groups = new Map<string, PairAgg>();

  if (canScanEvents) {
    const { data: evts } = await sb
      .from("events")
      .select("src_ip, dest_ip, kill_chain_phase")
      .eq("run_id", runId)
      .not("kill_chain_phase", "is", null)
      .limit(EVENT_SCAN_CAP);

    for (const ev of evts ?? []) {
      if (!ev.kill_chain_phase) continue;
      const pair = directedPair(ev.src_ip, ev.dest_ip, attackerIps, victimIps);
      if (!pair) continue;
      const key = pairKey(pair.attackerIp, pair.victimIp);
      const agg = groups.get(key) ?? {
        attackerIp: pair.attackerIp,
        victimIp: pair.victimIp,
        phases: new Set<string>(),
        count: 0,
      };
      const phase = normalizePhase(ev.kill_chain_phase);
      if (phase) agg.phases.add(phase);
      agg.count += 1;
      groups.set(key, agg);
    }
  }

  const suppressed = [...groups.values()].filter((g) => g.phases.size === 1).length;

  let campaigns: KnownCampaign[];
  let mode: GroundTruthMode;

  if (truth) {
    mode = "declared";

    const comparisons = compareToGroundTruth(
      truth,
      rows
        // An incident an analyst rejected must not satisfy a declared campaign.
        .filter((r) => r.status !== "false_positive")
        .map((r) => ({
          attackerIp: r.attacker_ip,
          victimIp: r.victim_ip,
          phases: canonicalPhases(r.phases_detected),
        })),
    );

    campaigns = comparisons.map((cmp) => {
      const hit = rows.find(
        (r) =>
          r.status !== "false_positive" &&
          samePair(
            cmp.campaign.attackerIp,
            cmp.campaign.victimIp,
            r.attacker_ip,
            r.victim_ip,
          ),
      );
      const agg =
        groups.get(pairKey(cmp.campaign.attackerIp, cmp.campaign.victimIp)) ??
        groups.get(pairKey(cmp.campaign.victimIp, cmp.campaign.attackerIp));

      return {
        attackerIp: cmp.campaign.attackerIp,
        victimIp: cmp.campaign.victimIp,
        found: cmp.found,
        incidentId: hit?.id ?? null,
        phasesDetected: cmp.detectedPhases,
        phaseCount: cmp.detectedPhases.length,
        eventCount: hit?.event_count ?? agg?.count ?? 0,
        severity: hit?.severity ?? null,
        expectedPhases: cmp.campaign.expectedPhases,
        missingPhases: cmp.missingPhases,
        unexpectedPhases: cmp.unexpectedPhases,
        note: cmp.campaign.note ?? null,
      };
    });
  } else {
    mode = "derived";

    const eligible = [...groups.values()].filter((g) => g.phases.size >= 2);
    const basis =
      canScanEvents && groups.size > 0
        ? eligible
        : rows.map((r) => ({
            attackerIp: r.attacker_ip,
            victimIp: r.victim_ip,
            phases: new Set(canonicalPhases(r.phases_detected)),
            count: r.event_count,
          }));

    campaigns = basis.map((pair) => {
      const hit = rows.find((r) =>
        samePair(pair.attackerIp, pair.victimIp, r.attacker_ip, r.victim_ip),
      );
      const phases = hit?.phases_detected?.length
        ? canonicalPhases(hit.phases_detected)
        : sortPhases([...pair.phases]);

      return {
        attackerIp: pair.attackerIp,
        victimIp: pair.victimIp,
        found: Boolean(hit) && hit?.status !== "false_positive",
        incidentId: hit?.id ?? null,
        phasesDetected: phases,
        phaseCount: phases.length,
        eventCount: hit?.event_count ?? pair.count,
        severity: hit?.severity ?? null,
        // Derived mode has no independent expectation to compare against.
        expectedPhases: [],
        missingPhases: [],
        unexpectedPhases: [],
        note: null,
      };
    });
  }

  const reconstructed = campaigns.filter((c) => c.found).length;
  const missed = campaigns.filter((c) => !c.found).length;
  const partial = campaigns.filter(
    (c) => c.found && c.missingPhases.length > 0,
  ).length;

  const hasActivity = mode === "declared" || (canScanEvents && groups.size > 0);

  const incidentsOut: EvalIncident[] = rows.map((r) => {
    const matchesExpected = campaigns.some((c) =>
      samePair(c.attackerIp, c.victimIp, r.attacker_ip, r.victim_ip),
    );
    const status = r.status ?? "new";

    let result: EvalIncident["result"];
    if (status === "false_positive") result = "false_positive";
    else if (hasActivity && matchesExpected) result = "reconstructed";
    else if (hasActivity && !matchesExpected) result = "extra";
    else if (status === "resolved") result = "reconstructed";
    else result = "unreviewed";

    return {
      id: r.id,
      attackerIp: r.attacker_ip,
      victimIp: r.victim_ip,
      severity: r.severity,
      riskScore: r.risk_score,
      phasesDetected: canonicalPhases(r.phases_detected),
      eventCount: r.event_count,
      summary: r.summary,
      status,
      result,
    };
  });

  const extra = incidentsOut.filter((i) => i.result === "extra").length;
  const markedFp = incidentsOut.filter((i) => i.result === "false_positive").length;
  const unreviewed = incidentsOut.filter((i) => i.result === "unreviewed").length;

  const totalEvents = run.event_count || storedEvents || classifiedEvents;
  const totalIncidents = rows.length;
  const reduction =
    totalIncidents > 0
      ? Math.round(classifiedEvents / totalIncidents)
      : classifiedEvents;

  return {
    runId: run.id,
    runLabel: run.label,
    groundTruthMode: mode,
    groundTruthLabel: truth?.label ?? null,
    hasGroundTruth: mode === "declared" || hasActivity || rows.length > 0,
    totalEvents,
    classifiedEvents,
    totalIncidents,
    reduction,
    reconstructed,
    extra,
    missed,
    suppressed,
    partial,
    truePositives: reconstructed,
    falsePositives: extra + markedFp,
    falseNegatives: missed,
    unreviewed,
    campaigns,
    incidents: incidentsOut,
  };
}
