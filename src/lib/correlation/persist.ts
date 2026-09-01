import { createClient } from '@supabase/supabase-js';
import type { NormalizedEvent, Incident } from './types';

const CANONICAL_PHASES: Record<string, string> = {
  reconnaissance: 'reconnaissance',
  recon: 'reconnaissance',
  scanning: 'reconnaissance',
  discovery: 'reconnaissance',
  delivery: 'delivery',
  weaponization: 'delivery',
  exploitation: 'exploitation',
  exploit: 'exploitation',
  execution: 'exploitation',
  persistence: 'persistence',
  installation: 'persistence',
  command_and_control: 'command_and_control',
  'command-and-control': 'command_and_control',
  c2: 'command_and_control',
  cnc: 'command_and_control',
};

function normalizePhase(phase: string | undefined | null): string | null {
  if (!phase) return null;
  const key = phase.toLowerCase().trim().replace(/[\s-]+/g, '_');
  return CANONICAL_PHASES[key] ?? key;
}

const CANONICAL_SOURCES: Record<string, string> = {
  suricata: 'suricata',
  'suricata eve': 'suricata',
  'suricata-eve': 'suricata',
  windows_security: 'windows_security',
  'windows security': 'windows_security',
  winevt: 'windows_security',
  powershell: 'powershell',
  'windows powershell': 'powershell',
};

function normalizeSource(source: string): string {
  const key = source.toLowerCase().trim();
  return CANONICAL_SOURCES[key] ?? key;
}

function getAdminClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    throw new Error(
      'Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY'
    );
  }
  return createClient(url, key);
}

const BATCH_SIZE = 500;

export interface RunConfig {
  label: string;
  sourceType?: string;
  attackerIps: string[];
  victimIps: string[];
  c2Ports: number[];
  connectionId?: string;
}

export async function createRun(config: RunConfig): Promise<string> {
  const sb = getAdminClient();
  const { data, error } = await sb
    .from('correlation_runs')
    .insert({
      label: config.label,
      source_type: config.sourceType ?? 'file',
      attacker_ips: config.attackerIps,
      victim_ips: config.victimIps,
      c2_ports: config.c2Ports,
      status: 'running',
      connection_id: config.connectionId ?? null,
    })
    .select('id')
    .single();

  if (error || !data) {
    throw new Error(`Failed to create run: ${error?.message}`);
  }

  console.log(`[persist] Run ${data.id} created: "${config.label}"`);
  return data.id;
}

export async function completeRun(
  runId: string,
  events: NormalizedEvent[],
  incidentCount: number
): Promise<void> {
  const sourceCounts: Record<string, number> = {};
  const phaseCounts: Record<string, number> = {};
  for (const ev of events) {
    sourceCounts[ev.source] = (sourceCounts[ev.source] ?? 0) + 1;
    if (ev.killChainPhase) {
      phaseCounts[ev.killChainPhase] = (phaseCounts[ev.killChainPhase] ?? 0) + 1;
    }
  }

  const sb = getAdminClient();
  const { error } = await sb
    .from('correlation_runs')
    .update({
      status: 'completed',
      event_count: events.length,
      incident_count: incidentCount,
      source_counts: sourceCounts,
      phase_counts: phaseCounts,
      completed_at: new Date().toISOString(),
    })
    .eq('id', runId);

  if (error) {
    console.error(`[persist] Failed to complete run: ${error.message}`);
  }
}

export async function failRun(runId: string, errorMsg: string): Promise<void> {
  const sb = getAdminClient();
  const { error } = await sb
    .from('correlation_runs')
    .update({
      status: 'failed',
      error: errorMsg,
      completed_at: new Date().toISOString(),
    })
    .eq('id', runId);

  if (error) {
    console.error(`[persist] Failed to mark run as failed: ${error.message}`);
  }
}

export async function persistEvents(
  events: NormalizedEvent[],
  runId: string
): Promise<Map<NormalizedEvent, string>> {
  const sb = getAdminClient();
  const eventIdMap = new Map<NormalizedEvent, string>();

  console.log(`[persist] Inserting ${events.length} events in batches of ${BATCH_SIZE}...`);

  for (let i = 0; i < events.length; i += BATCH_SIZE) {
    const batch = events.slice(i, i + BATCH_SIZE);
    const rows = batch.map((ev) => ({
      run_id: runId,
      source: normalizeSource(ev.source),
      event_time: ev.eventTime,
      event_type: ev.eventType ?? null,
      event_id: ev.eventId ?? null,
      src_ip: ev.srcIp ?? null,
      dest_ip: ev.destIp ?? null,
      src_port: ev.srcPort ?? null,
      dest_port: ev.destPort ?? null,
      proto: ev.proto ?? null,
      signature: ev.signature ?? null,
      category: ev.category ?? null,
      message: ev.message?.substring(0, 500) ?? null,
      kill_chain_phase: normalizePhase(ev.killChainPhase),
    }));

    const { data, error } = await sb.from('events').insert(rows).select('id');

    if (error) {
      console.error(`[persist] Batch ${i / BATCH_SIZE + 1} failed:`, error.message);
      continue;
    }

    if (data) {
      data.forEach((row, j) => {
        eventIdMap.set(batch[j], row.id);
      });
    }

    if ((i / BATCH_SIZE) % 50 === 0 && i > 0) {
      console.log(`[persist]   ... ${i} / ${events.length} events inserted`);
    }
  }

  console.log(`[persist] ${eventIdMap.size} events inserted successfully`);
  return eventIdMap;
}

export async function persistIncidents(
  incidents: Incident[],
  eventIdMap: Map<NormalizedEvent, string>,
  runId: string
): Promise<void> {
  const sb = getAdminClient();

  for (const inc of incidents) {
    const { data: incData, error: incErr } = await sb
      .from('incidents')
      .insert({
        run_id: runId,
        attacker_ip: inc.attackerIp,
        victim_ip: inc.victimIp,
        first_seen: inc.firstSeen,
        last_seen: inc.lastSeen,
        phases_detected: inc.phasesDetected,
        phase_count: inc.phaseCount,
        risk_score: inc.riskScore,
        severity: inc.severity,
        event_count: inc.eventCount,
        summary: inc.summary,
      })
      .select('id')
      .single();

    if (incErr || !incData) {
      console.error('[persist] Failed to insert incident:', incErr?.message);
      continue;
    }

    const incidentId = incData.id;
    console.log(`[persist] Incident ${incidentId} created (${inc.severity})`);

    const junctionRows = inc.events
      .filter((ev) => eventIdMap.has(ev))
      .map((ev) => ({
        incident_id: incidentId,
        event_id: eventIdMap.get(ev)!,
        phase: normalizePhase(ev.killChainPhase),
      }));

    for (let i = 0; i < junctionRows.length; i += BATCH_SIZE) {
      const batch = junctionRows.slice(i, i + BATCH_SIZE);
      const { error } = await sb.from('incident_events').insert(batch);
      if (error) {
        console.error(`[persist] incident_events batch failed:`, error.message);
      }
    }

    console.log(`[persist]   Linked ${junctionRows.length} events to incident`);
  }
}
