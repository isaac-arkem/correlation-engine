import type { NormalizedEvent, Incident } from './types';
import { getCorrelationConfig } from './config';
import { scoreRisk } from './score';

/**
 * correlate.ts — THE core contribution of this thesis.
 *
 * PROBLEM: A base ELK-based SIEM fires detection rules on individual events.
 * Each rule has no memory of other events — it sees one log line in isolation.
 * When an attacker runs a multi-stage campaign (scan → deliver payload →
 * execute commands → establish persistence → open C2 channel), the SIEM
 * produces hundreds of disconnected alerts. A human analyst must manually
 * piece them together to realise these are ONE coordinated attack, not
 * hundreds of unrelated issues.
 *
 * SOLUTION: This correlation engine takes phase-tagged events from multiple
 * sources (Suricata IDS + Windows Security + PowerShell), groups them by
 * (attacker_ip, victim_ip) pair, orders each group by time, and checks
 * whether the group spans multiple kill-chain phases. If it does, the
 * group represents a MULTI-STAGE INCIDENT — a single coordinated attack
 * campaign reconstructed from what the base SIEM saw as isolated alerts.
 *
 * The result: instead of hundreds of raw alerts, the SME operator sees a
 * handful of prioritised incidents, each with a plain-English summary of
 * what happened and a risk score.
 */

type PairKey = string;

function makePairKey(attackerIp: string, victimIp: string): PairKey {
  return `${attackerIp}→${victimIp}`;
}

function parsePairKey(key: PairKey): { attackerIp: string; victimIp: string } {
  const [attackerIp, victimIp] = key.split('→');
  return { attackerIp, victimIp };
}

/**
 * Determine the attacker/victim direction.
 *
 * For Suricata events the srcIp is typically the initiator. However,
 * C2 traffic is bidirectional — the victim calls back to the attacker's
 * listener. Both directions belong to the SAME incident, so we normalise
 * the pair to always read attacker→victim.
 *
 * For Windows/PowerShell events that lack IPs, we attribute them to the
 * victim side (they ran on the target machine) and merge them into the
 * primary network group later.
 */
function getDirectedPair(
  ev: NormalizedEvent
): { attackerIp: string; victimIp: string } | null {
  if (ev.source === 'suricata') {
    if (!ev.srcIp || !ev.destIp) return null;

    const cfg = getCorrelationConfig();

    // For traffic between known attacker/victim hosts, always normalise
    // to attacker→victim regardless of packet direction.
    const srcIsAttacker = cfg.attackerIps.includes(ev.srcIp);
    const srcIsVictim = cfg.victimIps.includes(ev.srcIp);
    const destIsAttacker = cfg.attackerIps.includes(ev.destIp);
    const destIsVictim = cfg.victimIps.includes(ev.destIp);

    if ((srcIsAttacker && destIsVictim) || (srcIsVictim && destIsAttacker)) {
      const attackerIp = srcIsAttacker ? ev.srcIp : ev.destIp;
      const victimIp = srcIsVictim ? ev.srcIp : ev.destIp;
      return { attackerIp, victimIp };
    }

    return { attackerIp: ev.srcIp, victimIp: ev.destIp };
  }

  // Windows/PowerShell events: no network IPs, merge into primary group later
  return null;
}

const PHASE_ORDER = [
  'reconnaissance',
  'delivery',
  'exploitation',
  'persistence',
  'command_and_control',
];

function phaseLabel(phase: string): string {
  const labels: Record<string, string> = {
    reconnaissance: 'scanned',
    delivery: 'delivered a payload to',
    exploitation: 'executed PowerShell enumeration/exploitation on',
    persistence: 'established persistence on',
    command_and_control: 'opened a C2 channel with',
  };
  return labels[phase] ?? phase;
}

function buildSummary(
  attackerIp: string,
  victimIp: string,
  phases: string[]
): string {
  const sorted = [...phases].sort(
    (a, b) => PHASE_ORDER.indexOf(a) - PHASE_ORDER.indexOf(b)
  );

  const actions = sorted.map((p) => phaseLabel(p));

  if (actions.length === 1) {
    return `Host ${attackerIp} ${actions[0]} ${victimIp}.`;
  }

  const allButLast = actions.slice(0, -1).join(', ');
  const last = actions[actions.length - 1];

  return `Host ${attackerIp} ${allButLast}, then ${last} ${victimIp} — a coordinated multi-stage attack.`;
}

export function correlate(events: NormalizedEvent[]): Incident[] {
  // Step 1: Keep only events that have a kill-chain phase assigned
  const phased = events.filter((e) => e.killChainPhase);

  // Step 2: Group by (attacker_ip, victim_ip)
  const networkGroups = new Map<PairKey, NormalizedEvent[]>();
  const endpointEvents: NormalizedEvent[] = [];

  for (const ev of phased) {
    const pair = getDirectedPair(ev);
    if (pair) {
      const key = makePairKey(pair.attackerIp, pair.victimIp);
      const group = networkGroups.get(key) ?? [];
      group.push(ev);
      networkGroups.set(key, group);
    } else {
      endpointEvents.push(ev);
    }
  }

  // Step 3: Merge endpoint events (Windows/PS — no IPs) into the primary
  // network group. Endpoint events ran on the victim machine and belong
  // to the same campaign as the network traffic targeting it.
  const cfg = getCorrelationConfig();
  if (endpointEvents.length > 0 && cfg.attackerIps.length > 0 && cfg.victimIps.length > 0) {
    const primaryKey = makePairKey(cfg.attackerIps[0], cfg.victimIps[0]);
    const primary = networkGroups.get(primaryKey) ?? [];
    primary.push(...endpointEvents);
    networkGroups.set(primaryKey, primary);
  }

  // Step 4: For each group, sort by time and check for multi-stage
  const incidents: Incident[] = [];

  for (const [key, group] of networkGroups) {
    group.sort((a, b) => a.eventTime.localeCompare(b.eventTime));

    const phases = [...new Set(group.map((e) => e.killChainPhase!))];

    // A group is a multi-stage incident if it has ≥ 2 distinct phases
    if (phases.length < 2) continue;

    const { attackerIp, victimIp } = parsePairKey(key);
    const firstSeen = group[0].eventTime;
    const lastSeen = group[group.length - 1].eventTime;

    const { riskScore, severity } = scoreRisk(phases, group);

    incidents.push({
      attackerIp,
      victimIp,
      firstSeen,
      lastSeen,
      phasesDetected: phases.sort(
        (a, b) => PHASE_ORDER.indexOf(a) - PHASE_ORDER.indexOf(b)
      ),
      phaseCount: phases.length,
      eventCount: group.length,
      riskScore,
      severity,
      summary: buildSummary(attackerIp, victimIp, phases),
      events: group,
    });
  }

  incidents.sort((a, b) => b.riskScore - a.riskScore);

  console.log(
    `[correlate] ${phased.length} phased events → ${networkGroups.size} groups → ${incidents.length} multi-stage incidents`
  );

  return incidents;
}
