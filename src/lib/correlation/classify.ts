import type { NormalizedEvent } from './types';
import { getCorrelationConfig } from './config';

/**
 * Kill-chain phase classification.
 *
 * Each event is tagged with the phase it most likely belongs to,
 * using the configured attacker/victim IPs (defaults to the experiment
 * hosts 192.168.64.2 → 192.168.64.3, configurable via env vars).
 *
 * Phases follow the Cyber Kill Chain model (detectable subset):
 *   reconnaissance → delivery → exploitation → persistence → command_and_control
 *
 * An event that doesn't match any phase is left unclassified (undefined).
 */

const SCAN_SIGNATURES = [
  'scan', 'nmap', 'portscan', 'port scan', 'network scan',
  'icmpv4 unknown code', 'ping',
];

const RECON_CATEGORIES = [
  'attempted-recon', 'network scan', 'misc activity',
  'generic protocol command decode',
];

const EXPLOITATION_MARKERS = [
  'get-process', 'get-localuser', 'get-nettcpconnection',
  'get-ciminstance', 'encodedcommand', 'invoke-expression',
  'invoke-webrequest', 'downloadstring', 'downloadfile',
  'iex(', 'iex (', 'bypass', 'reverse', 'meterpreter',
  'shellcode', 'mimikatz', 'powerview', 'bloodhound',
  'net user', 'net localgroup', 'whoami', 'systeminfo',
  'win32_startupcommand',
];

const PERSISTENCE_MARKERS = [
  'windowsupdate', 'currentversion\\run', 'currentversion/run',
  'schtasks', 'new-service', 'set-itemproperty',
  'startup', 'hklm\\software\\microsoft\\windows\\currentversion',
  'reg add', 'new-scheduledtask',
];

function isKnownAttacker(ip: string | undefined): boolean {
  if (!ip) return false;
  return getCorrelationConfig().attackerIps.includes(ip);
}

function isKnownVictim(ip: string | undefined): boolean {
  if (!ip) return false;
  return getCorrelationConfig().victimIps.includes(ip);
}

function isKnownPair(ipA: string | undefined, ipB: string | undefined): boolean {
  return (isKnownAttacker(ipA) && isKnownVictim(ipB)) ||
         (isKnownAttacker(ipB) && isKnownVictim(ipA));
}

function isC2Port(port: number): boolean {
  return getCorrelationConfig().c2Ports.has(port);
}

export function classifyPhase(event: NormalizedEvent): string | undefined {
  if (event.source === 'suricata') {
    return classifySuricata(event);
  }
  if (event.source === 'powershell') {
    return classifyPowerShell(event);
  }
  if (event.source === 'windows_security') {
    return classifyWindowsSecurity(event);
  }
  return undefined;
}

function classifySuricata(ev: NormalizedEvent): string | undefined {
  const srcIp = ev.srcIp;
  const destIp = ev.destIp;
  const srcPort = ev.srcPort ?? 0;
  const destPort = ev.destPort ?? 0;
  const sig = (ev.signature ?? '').toLowerCase();
  const cat = (ev.category ?? '').toLowerCase();
  const eventType = ev.eventType;

  // C2: traffic on known C2 ports between configured hosts —
  // but only if the connection was actually established (has data transfer).
  // SYN-only probes to C2 ports during a scan are recon, not C2.
  if (isC2Port(destPort) || isC2Port(srcPort)) {
    if (isKnownPair(srcIp, destIp)) {
      if (eventType === 'flow') {
        const raw = ev.raw as Record<string, unknown>;
        const flow = raw.flow as Record<string, unknown> | undefined;
        const pktsToServer = (flow?.pkts_toserver as number) ?? 0;
        const pktsToClient = (flow?.pkts_toclient as number) ?? 0;
        if (pktsToServer + pktsToClient > 4) return 'command_and_control';
        return 'reconnaissance';
      }
      return 'command_and_control';
    }
  }

  // SMB events between known hosts — reconnaissance (service enumeration)
  if (eventType === 'smb') {
    if (isKnownPair(srcIp, destIp)) {
      return 'reconnaissance';
    }
  }

  // Alerts
  if (eventType === 'alert') {
    if (SCAN_SIGNATURES.some((s) => sig.includes(s))) return 'reconnaissance';
    if (RECON_CATEGORIES.some((c) => cat.includes(c))) return 'reconnaissance';

    if (isKnownAttacker(srcIp) && isKnownVictim(destIp)) return 'reconnaissance';
    if (isKnownVictim(srcIp) && isKnownAttacker(destIp) && !isC2Port(destPort)) {
      return 'reconnaissance';
    }
  }

  // HTTP events — payload delivery between known hosts,
  // or fetching executable payloads from any host
  if (eventType === 'http') {
    const raw = ev.raw as Record<string, unknown>;
    const http = raw.http as Record<string, unknown> | undefined;
    const url = ((http?.url as string) ?? '').toLowerCase();

    if (isKnownPair(srcIp, destIp)) {
      return 'delivery';
    }
    if (url.includes('.exe') || url.includes('.ps1') || url.includes('.bat')) {
      return 'delivery';
    }
  }

  // Flow events — scan patterns: SYN-only probes (no response) to many ports
  if (eventType === 'flow') {
    if (isKnownAttacker(srcIp) && isKnownVictim(destIp)) {
      const raw = ev.raw as Record<string, unknown>;
      const tcp = raw.tcp as Record<string, unknown> | undefined;
      const state = tcp?.state as string | undefined;
      const flow = raw.flow as Record<string, unknown> | undefined;
      const pktsToServer = (flow?.pkts_toserver as number) ?? 0;
      const pktsToClient = (flow?.pkts_toclient as number) ?? 0;

      if (state === 'syn_sent' && pktsToClient === 0) {
        return 'reconnaissance';
      }
      if (state === 'closed' && pktsToServer <= 2 && pktsToClient <= 2) {
        return 'reconnaissance';
      }
    }
  }

  // Anomaly events between known hosts
  if (eventType === 'anomaly') {
    if (isKnownPair(srcIp, destIp)) {
      return 'command_and_control';
    }
  }

  return undefined;
}

function classifyPowerShell(ev: NormalizedEvent): string | undefined {
  const msg = (ev.message ?? '').toLowerCase();

  if (PERSISTENCE_MARKERS.some((m) => msg.includes(m))) return 'persistence';
  if (EXPLOITATION_MARKERS.some((m) => msg.includes(m))) return 'exploitation';

  return undefined;
}

function classifyWindowsSecurity(ev: NormalizedEvent): string | undefined {
  const eventId = ev.eventId;

  // Successful logon — supporting signal for valid-accounts access
  if (eventId === 4624) return 'exploitation';

  // Failed logon — brute force attempt
  if (eventId === 4625) return 'reconnaissance';

  // User group membership enumeration
  if (eventId === 4798) return 'exploitation';

  return undefined;
}

export function classifyAll(events: NormalizedEvent[]): NormalizedEvent[] {
  let classified = 0;
  for (const ev of events) {
    const phase = classifyPhase(ev);
    if (phase) {
      ev.killChainPhase = phase;
      classified++;
    }
  }
  console.log(
    `[classify] ${classified}/${events.length} events assigned a kill-chain phase`
  );
  return events;
}
