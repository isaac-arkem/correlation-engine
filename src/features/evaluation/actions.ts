"use server";

import { createSupabaseAdminClient } from "@/lib/supabase/server";

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
}

export interface EvaluationData {
  runId: string;
  runLabel: string;
  hasGroundTruth: boolean;
  totalEvents: number;
  classifiedEvents: number;
  totalIncidents: number;
  reduction: number;
  reconstructed: number;
  extra: number;
  missed: number;
  suppressed: number;
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

function samePair(a1: string, v1: string, a2: string, v2: string) {
  return (a1 === a2 && v1 === v2) || (a1 === v2 && v1 === a2);
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

export async function getEvaluationData(
  runId: string,
): Promise<EvaluationData | null> {
  const sb = createSupabaseAdminClient();

  const { data: run } = await sb
    .from("correlation_runs")
    .select(
      "id, label, attacker_ips, victim_ips, event_count, source_counts, phase_counts",
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
        .order("risk_score", { ascending: false }),
    ]);

  const rows = incidents ?? [];
  const attackerIps = (run.attacker_ips ?? []).filter(Boolean);
  const victimIps = (run.victim_ips ?? []).filter(Boolean);
  const classifiedEvents = classifiedCount ?? storedEvents ?? 0;
  const canScanEvents = classifiedEvents <= EVENT_SCAN_CAP;

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
      agg.phases.add(ev.kill_chain_phase);
      agg.count += 1;
      groups.set(key, agg);
    }
  }

  const eligible = [...groups.values()].filter((g) => g.phases.size >= 2);
  const suppressed = [...groups.values()].filter((g) => g.phases.size === 1).length;

  const campaigns: KnownCampaign[] = (
    canScanEvents && groups.size > 0
      ? eligible
      : rows.map((r) => ({
          attackerIp: r.attacker_ip,
          victimIp: r.victim_ip,
          phases: new Set(r.phases_detected ?? []),
          count: r.event_count,
        }))
  ).map((pair) => {
    const hit = rows.find((r) =>
      samePair(pair.attackerIp, pair.victimIp, r.attacker_ip, r.victim_ip),
    );
    const phases = hit?.phases_detected?.length
      ? hit.phases_detected
      : [...pair.phases];
    return {
      attackerIp: pair.attackerIp,
      victimIp: pair.victimIp,
      found: Boolean(hit) && hit?.status !== "false_positive",
      incidentId: hit?.id ?? null,
      phasesDetected: phases,
      phaseCount: phases.length,
      eventCount: hit?.event_count ?? pair.count,
      severity: hit?.severity ?? null,
    };
  });

  const reconstructed = campaigns.filter((c) => c.found).length;
  const missed = campaigns.filter((c) => !c.found).length;
  const hasActivity = canScanEvents && groups.size > 0;

  const incidentsOut: EvalIncident[] = rows.map((r) => {
    const matchesEligible = campaigns.some((c) =>
      samePair(c.attackerIp, c.victimIp, r.attacker_ip, r.victim_ip),
    );
    const status = r.status ?? "new";

    let result: EvalIncident["result"] = "unreviewed";
    if (status === "false_positive") result = "false_positive";
    else if (hasActivity && matchesEligible) result = "reconstructed";
    else if (hasActivity && !matchesEligible) result = "extra";
    else if (status === "resolved") result = "reconstructed";
    else result = "unreviewed";

    return {
      id: r.id,
      attackerIp: r.attacker_ip,
      victimIp: r.victim_ip,
      severity: r.severity,
      riskScore: r.risk_score,
      phasesDetected: r.phases_detected,
      eventCount: r.event_count,
      summary: r.summary,
      status,
      result,
    };
  });

  const extra = incidentsOut.filter((i) => i.result === "extra").length;
  const markedFp = incidentsOut.filter(
    (i) => i.result === "false_positive",
  ).length;
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
    hasGroundTruth: hasActivity || rows.length > 0,
    totalEvents,
    classifiedEvents,
    totalIncidents,
    reduction,
    reconstructed,
    extra,
    missed,
    suppressed,
    truePositives: reconstructed,
    falsePositives: extra + markedFp,
    falseNegatives: missed,
    unreviewed,
    campaigns,
    incidents: incidentsOut,
  };
}
