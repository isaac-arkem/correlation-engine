import type { NormalizedEvent } from './types';
import type { CorrelationConfig } from './config';

const COMMON_PORTS = new Set([
  22, 53, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017,
  25, 110, 143, 993, 995, 587,
]);

/**
 * Scan parsed events to auto-detect attacker IPs, victim IPs, and C2 ports.
 *
 * Strategy:
 * - Attacker: src_ip that appears most often in Suricata alerts
 * - Victim: dest_ip that receives the most Suricata alerts
 * - C2 ports: non-standard dest ports with high traffic volume between
 *   the detected attacker/victim pair
 */
export function autoDetectConfig(events: NormalizedEvent[]): CorrelationConfig {
  const alertSrc = new Map<string, number>();
  const alertDest = new Map<string, number>();

  for (const ev of events) {
    if (ev.source === 'suricata' && ev.signature) {
      if (ev.srcIp) alertSrc.set(ev.srcIp, (alertSrc.get(ev.srcIp) ?? 0) + 1);
      if (ev.destIp) alertDest.set(ev.destIp, (alertDest.get(ev.destIp) ?? 0) + 1);
    }
  }

  const attackerIps = topKeys(alertSrc, 3);
  const victimIps = topKeys(alertDest, 3).filter((ip) => !attackerIps.includes(ip));

  // If no alerts found, fall back to most frequent src/dest across all events
  if (attackerIps.length === 0) {
    const allSrc = new Map<string, number>();
    const allDest = new Map<string, number>();
    for (const ev of events) {
      if (ev.srcIp) allSrc.set(ev.srcIp, (allSrc.get(ev.srcIp) ?? 0) + 1);
      if (ev.destIp) allDest.set(ev.destIp, (allDest.get(ev.destIp) ?? 0) + 1);
    }
    attackerIps.push(...topKeys(allSrc, 3));
    victimIps.push(...topKeys(allDest, 3).filter((ip) => !attackerIps.includes(ip)));
  }

  // C2 ports: non-standard ports with high traffic between attacker → victim
  const attackerSet = new Set(attackerIps);
  const victimSet = new Set(victimIps);
  const portHits = new Map<number, number>();

  for (const ev of events) {
    if (
      ev.destPort &&
      ev.destPort > 1024 &&
      !COMMON_PORTS.has(ev.destPort) &&
      attackerSet.has(ev.srcIp ?? '') &&
      victimSet.has(ev.destIp ?? '')
    ) {
      portHits.set(ev.destPort, (portHits.get(ev.destPort) ?? 0) + 1);
    }
  }

  const c2Ports = [...portHits.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([port]) => port);

  console.log(`[auto-detect] Attackers: ${attackerIps.join(', ') || 'none found'}`);
  console.log(`[auto-detect] Victims: ${victimIps.join(', ') || 'none found'}`);
  console.log(`[auto-detect] C2 ports: ${c2Ports.join(', ') || 'none found'}`);

  return {
    attackerIps,
    victimIps,
    c2Ports: new Set(c2Ports),
  };
}

function topKeys<V extends number>(map: Map<string, V>, n: number): string[] {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k]) => k);
}
