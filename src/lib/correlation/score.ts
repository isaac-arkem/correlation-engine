import type { NormalizedEvent } from './types';

/**
 * Risk scoring model for multi-stage incidents.
 *
 * Formula:
 *   risk = clamp(
 *     phaseCount / TOTAL_PHASES * 50  — breadth: more phases = broader attack
 *     + 15 * (has exploitation)       — exploitation means code execution achieved
 *     + 15 * (has persistence)        — persistence means the attacker intends to stay
 *     + 15 * (has C2)                 — C2 means active remote control established
 *     + min(10, velocityBonus),       — faster attacks are harder to respond to
 *     0, 100
 *   )
 *
 * TOTAL_PHASES = 5 (the detectable subset of the Lockheed Martin Kill Chain).
 * Weaponization is excluded because it occurs offline on the attacker's
 * machine and is unobservable from network/endpoint telemetry. Actions on
 * Objectives requires DLP integration beyond the scope of this engine.
 *
 * Severity thresholds:
 *   ≥ 80 → critical
 *   ≥ 60 → high
 *   ≥ 40 → medium
 *   else → low
 *
 * Rationale: The formula weights both breadth (how many kill-chain phases
 * the attacker completed) and depth (whether they achieved the most
 * dangerous milestones). Velocity rewards detection of fast-moving attacks
 * that leave less time for human response.
 */

const TOTAL_PHASES = 5;

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export function scoreRisk(
  phases: string[],
  events: NormalizedEvent[]
): { riskScore: number; severity: 'low' | 'medium' | 'high' | 'critical' } {
  const phaseCount = phases.length;
  const phaseSet = new Set(phases);

  const breadth = (phaseCount / TOTAL_PHASES) * 50;

  const hasExploitation = phaseSet.has('exploitation') ? 15 : 0;
  const hasPersistence = phaseSet.has('persistence') ? 15 : 0;
  const hasC2 = phaseSet.has('command_and_control') ? 15 : 0;

  // Velocity: how fast the attack progressed across phases
  let velocityBonus = 0;
  if (events.length >= 2) {
    const first = new Date(events[0].eventTime).getTime();
    const last = new Date(events[events.length - 1].eventTime).getTime();
    const durationHours = (last - first) / (1000 * 60 * 60);
    // Faster attacks get a higher bonus (max 10 points)
    if (durationHours <= 1) velocityBonus = 10;
    else if (durationHours <= 6) velocityBonus = 7;
    else if (durationHours <= 24) velocityBonus = 4;
    else velocityBonus = 1;
  }

  const riskScore = Math.round(
    clamp(breadth + hasExploitation + hasPersistence + hasC2 + velocityBonus, 0, 100)
  );

  let severity: 'low' | 'medium' | 'high' | 'critical';
  if (riskScore >= 80) severity = 'critical';
  else if (riskScore >= 60) severity = 'high';
  else if (riskScore >= 40) severity = 'medium';
  else severity = 'low';

  return { riskScore, severity };
}
