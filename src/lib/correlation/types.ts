export interface NormalizedEvent {
  source: 'suricata' | 'windows_security' | 'powershell';
  eventTime: string; // ISO 8601
  eventType?: string;
  eventId?: number;
  srcIp?: string;
  destIp?: string;
  srcPort?: number;
  destPort?: number;
  proto?: string;
  signature?: string;
  category?: string;
  message?: string;
  killChainPhase?: string;
  raw?: unknown;
}

export interface EventSource {
  getSecurityEvents(range?: {
    from?: string;
    to?: string;
  }): Promise<NormalizedEvent[]>;
}

export interface Incident {
  attackerIp: string;
  victimIp: string;
  firstSeen: string;
  lastSeen: string;
  phasesDetected: string[];
  phaseCount: number;
  eventCount: number;
  riskScore: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  summary: string;
  events: NormalizedEvent[];
}

export interface IncidentRow {
  id?: string;
  attacker_ip: string;
  victim_ip: string;
  first_seen: string;
  last_seen: string;
  phases_detected: string[];
  phase_count: number;
  risk_score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  event_count: number;
  summary: string;
}

export interface EventRow {
  id?: string;
  source: 'suricata' | 'windows_security' | 'powershell';
  event_time: string;
  event_type?: string;
  event_id?: number;
  src_ip?: string;
  dest_ip?: string;
  src_port?: number;
  dest_port?: number;
  proto?: string;
  signature?: string;
  category?: string;
  message?: string;
  kill_chain_phase?: string;
}
