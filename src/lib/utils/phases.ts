export interface PhaseMeta {
  key: string;
  label: string;
  shortLabel: string;
  color: string;
  description: string;
  order: number;
}

const PHASE_LIST: PhaseMeta[] = [
  {
    key: 'reconnaissance',
    label: 'Reconnaissance',
    shortLabel: 'Recon',
    color: '#60a5fa',
    description:
      'The attacker scanned the network looking for open ports, services, and vulnerabilities.',
    order: 1,
  },
  {
    key: 'delivery',
    label: 'Delivery',
    shortLabel: 'Delivery',
    color: '#a88940',
    description:
      'Malicious payloads or exploit tools were sent to the target system.',
    order: 2,
  },
  {
    key: 'exploitation',
    label: 'Exploitation',
    shortLabel: 'Exploit',
    color: '#c55f5f',
    description:
      'Vulnerabilities were exploited to gain unauthorized access or execute commands.',
    order: 3,
  },
  {
    key: 'persistence',
    label: 'Persistence',
    shortLabel: 'Persist',
    color: '#d68080',
    description:
      'The attacker installed backdoors or modified the system to maintain access after reboot.',
    order: 4,
  },
  {
    key: 'command_and_control',
    label: 'Command & Control',
    shortLabel: 'C2',
    color: '#ef4444',
    description:
      'The compromised system communicated back to the attacker for remote control.',
    order: 5,
  },
];

export const PHASES = PHASE_LIST;

export const PHASE_KEYS = PHASE_LIST.map((p) => p.key);

export const PHASE_MAP: Record<string, PhaseMeta> = Object.fromEntries(
  PHASE_LIST.map((p) => [p.key, p]),
);

export function phaseLabel(phase: string): string {
  return PHASE_MAP[phase]?.label ?? phase.replace(/_/g, ' ');
}

export function phaseShortLabel(phase: string): string {
  return PHASE_MAP[phase]?.shortLabel ?? phase.replace(/_/g, ' ');
}

export function phaseColor(phase: string): string {
  return PHASE_MAP[phase]?.color ?? '#737373';
}

export function phaseOrder(phase: string): number {
  return PHASE_MAP[phase]?.order ?? 99;
}

export function sourceLabel(source: string): string {
  const labels: Record<string, string> = {
    suricata: 'Suricata IDS',
    windows_security: 'Windows Security',
    powershell: 'PowerShell',
  };
  return labels[source] ?? source.replace(/_/g, ' ');
}
