export interface CorrelationConfig {
  attackerIps: string[];
  victimIps: string[];
  c2Ports: Set<number>;
}

let cached: CorrelationConfig | null = null;

export function getCorrelationConfig(): CorrelationConfig {
  if (cached) return cached;

  cached = {
    attackerIps: parseList(process.env.KNOWN_ATTACKER_IPS, []),
    victimIps: parseList(process.env.KNOWN_VICTIM_IPS, []),
    c2Ports: new Set(
      parseList(process.env.KNOWN_C2_PORTS, []).map((p) => parseInt(p, 10)).filter((n) => !isNaN(n))
    ),
  };

  return cached;
}

export function setCorrelationConfig(config: CorrelationConfig): void {
  cached = config;
}

export function resetConfigCache(): void {
  cached = null;
}

function parseList(envVar: string | undefined, fallback: string[]): string[] {
  if (!envVar) return fallback;
  return envVar.split(',').map((s) => s.trim()).filter(Boolean);
}
