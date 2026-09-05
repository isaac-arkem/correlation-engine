'use server';

import { createSupabaseAdminClient } from '@/lib/supabase/server';

export interface CorrelationRun {
  id: string;
  label: string;
  sourceType: string;
  eventCount: number;
  incidentCount: number;
  status: 'running' | 'completed' | 'failed';
  createdAt: string;
  completedAt: string | null;
}

export interface OverviewStats {
  totalEvents: number;
  classifiedEvents: number;
  bySource: Record<string, number>;
  byPhase: Record<string, number>;
  incidentCount: number;
  bySeverity: Record<string, number>;
  unreviewedCritical: number;
}

export type IncidentStatus = 'new' | 'investigating' | 'resolved' | 'false_positive';

export interface IncidentSummary {
  id: string;
  attackerIp: string;
  victimIp: string;
  firstSeen: string;
  lastSeen: string;
  phasesDetected: string[];
  phaseCount: number;
  riskScore: number;
  severity: string;
  eventCount: number;
  summary: string;
  status: IncidentStatus;
  statusChangedAt: string | null;
  statusChangedBy: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  events: EventRow[];
  phaseBreakdown: Record<string, number>;
}

export interface EventRow {
  id: string;
  source: string;
  eventTime: string;
  eventType: string | null;
  eventId: number | null;
  srcIp: string | null;
  destIp: string | null;
  srcPort: number | null;
  destPort: number | null;
  proto: string | null;
  signature: string | null;
  category: string | null;
  message: string | null;
  killChainPhase: string | null;
}

export async function getCorrelationRuns(): Promise<CorrelationRun[]> {
  const sb = createSupabaseAdminClient();
  const { data } = await sb
    .from('correlation_runs')
    .select('*')
    .order('created_at', { ascending: false });

  const runs = data ?? [];

  // Live counts so the dropdown is always accurate. One grouped pass rather
  // than two exact-count queries per run — the N+1 form cost ~7 s per page
  // load on runs with large event counts.
  const counts = new Map<string, { eventCount: number; incidentCount: number }>();

  const { data: countRows, error: countErr } = await sb.rpc('get_run_counts');

  if (!countErr && countRows) {
    for (const row of countRows) {
      counts.set(row.run_id, {
        eventCount: Number(row.event_count) || 0,
        incidentCount: Number(row.incident_count) || 0,
      });
    }
  } else {
    // Fallback for databases without add_dashboard_perf.sql applied: use the
    // counts cached on the run record rather than reintroducing the N+1.
    for (const row of runs) {
      counts.set(row.id, {
        eventCount: row.event_count ?? 0,
        incidentCount: row.incident_count ?? 0,
      });
    }
  }

  return runs.map((row) => ({
    id: row.id,
    label: row.label,
    sourceType: row.source_type,
    eventCount: counts.get(row.id)?.eventCount ?? 0,
    incidentCount: counts.get(row.id)?.incidentCount ?? 0,
    status: row.status as CorrelationRun['status'],
    createdAt: row.created_at,
    completedAt: row.completed_at,
  }));
}

export async function getLatestRunId(): Promise<string | null> {
  const sb = createSupabaseAdminClient();
  const { data } = await sb
    .from('correlation_runs')
    .select('id')
    .eq('status', 'completed')
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  return data?.id ?? null;
}

export async function getOverviewStats(
  runId: string,
  from?: string,
  to?: string
): Promise<OverviewStats> {
  const sb = createSupabaseAdminClient();

  // Load the run's cached stats + incidents in parallel
  const [{ data: run }, { data: incidents }] = await Promise.all([
    sb.from('correlation_runs').select('event_count, source_counts, phase_counts').eq('id', runId).single(),
    (() => {
      let q = sb.from('incidents').select('severity, status').eq('run_id', runId);
      if (from) q = q.gte('first_seen', from);
      if (to) q = q.lte('last_seen', to);
      return q;
    })(),
  ]);

  const srcObj = (run?.source_counts ?? {}) as Record<string, number>;
  const phaseObj = (run?.phase_counts ?? {}) as Record<string, number>;
  const hasCached = Object.keys(srcObj).length > 0 || Object.keys(phaseObj).length > 0;

  let bySource: Record<string, number> = {};
  let byPhase: Record<string, number> = {};
  let totalEvents = run?.event_count ?? 0;
  let classified = 0;

  if (hasCached && !from && !to) {
    // Use cached counts (fast, works for large datasets like legacy)
    for (const [k, v] of Object.entries(srcObj)) {
      if (v > 0) bySource[k] = v;
    }
    for (const [k, v] of Object.entries(phaseObj)) {
      if (v > 0) {
        byPhase[k] = v;
        classified += v;
      }
    }
  } else {
    // A date range (or a run with no cached counts) needs counts over the
    // filtered set. Aggregate in Postgres: fetching rows to count them in JS
    // was slow AND wrong — PostgREST caps a response at a fixed row limit well
    // below the requested one, so the counts came from a small sample.
    const { data: stats, error } = await sb.rpc('get_overview_stats', {
      p_run_id: runId,
      from_date: from ?? null,
      to_date: to ?? null,
    });

    if (!error && stats) {
      const s = stats;
      bySource = s.by_source ?? {};
      byPhase = s.by_phase ?? {};
      totalEvents = Number(s.total) || 0;
      classified = Number(s.classified) || 0;
    } else {
      // Fallback for databases without add_dashboard_perf.sql applied. Capped
      // and approximate — the RPC path above is the correct one.
      let q = sb.from('events').select('source, kill_chain_phase').eq('run_id', runId);
      if (from) q = q.gte('event_time', from);
      if (to) q = q.lte('event_time', to);
      const { data: evts } = await q.limit(1000);

      for (const ev of evts ?? []) {
        if (ev.source) bySource[ev.source] = (bySource[ev.source] ?? 0) + 1;
        if (ev.kill_chain_phase) {
          byPhase[ev.kill_chain_phase] = (byPhase[ev.kill_chain_phase] ?? 0) + 1;
          classified++;
        }
      }
      totalEvents = (evts ?? []).length;
    }
  }

  const bySeverity: Record<string, number> = {};
  let unreviewedCritical = 0;
  for (const inc of incidents ?? []) {
    bySeverity[inc.severity] = (bySeverity[inc.severity] ?? 0) + 1;
    if (
      (inc.severity === 'critical' || inc.severity === 'high') &&
      inc.status === 'new'
    ) {
      unreviewedCritical++;
    }
  }

  return {
    totalEvents,
    classifiedEvents: classified,
    bySource,
    byPhase,
    incidentCount: incidents?.length ?? 0,
    bySeverity,
    unreviewedCritical,
  };
}

export async function getIncidents(
  runId: string,
  from?: string,
  to?: string
): Promise<IncidentSummary[]> {
  const sb = createSupabaseAdminClient();

  let query = sb
    .from('incidents')
    .select('*')
    .eq('run_id', runId)
    .order('risk_score', { ascending: false });

  if (from) query = query.gte('first_seen', from);
  if (to) query = query.lte('last_seen', to);

  const { data } = await query;

  return (data ?? []).map((row) => ({
    id: row.id,
    attackerIp: row.attacker_ip,
    victimIp: row.victim_ip,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    phasesDetected: row.phases_detected,
    phaseCount: row.phase_count,
    riskScore: row.risk_score,
    severity: row.severity,
    eventCount: row.event_count,
    summary: row.summary,
    status: (row.status ?? 'new') as IncidentStatus,
    statusChangedAt: row.status_changed_at,
    statusChangedBy: row.status_changed_by,
  }));
}

function mapEventRow(ev: Record<string, unknown>): EventRow {
  return {
    id: ev.id as string,
    source: ev.source as string,
    eventTime: ev.event_time as string,
    eventType: ev.event_type as string | null,
    eventId: ev.event_id as number | null,
    srcIp: ev.src_ip as string | null,
    destIp: ev.dest_ip as string | null,
    srcPort: ev.src_port as number | null,
    destPort: ev.dest_port as number | null,
    proto: ev.proto as string | null,
    signature: ev.signature as string | null,
    category: ev.category as string | null,
    message: ev.message as string | null,
    killChainPhase: ev.kill_chain_phase as string | null,
  };
}

export async function getIncidentById(
  id: string
): Promise<IncidentDetail | null> {
  const sb = createSupabaseAdminClient();

  const { data: inc } = await sb
    .from('incidents')
    .select('*')
    .eq('id', id)
    .single();

  if (!inc) return null;

  const { data: phaseData } = await sb.rpc('get_incident_phase_breakdown', {
    p_incident_id: id,
  });
  const phaseBreakdown = (phaseData as Record<string, number> | null) ?? {};

  const { data: eventRows, error: rpcError } = await sb.rpc('get_incident_events', {
    p_incident_id: id,
    max_non_recon: 500,
    max_recon: 50,
  });

  let events: EventRow[];
  if (rpcError) {
    const { data: junctionRows } = await sb
      .from('incident_events')
      .select('event_id')
      .eq('incident_id', id);

    const eventIds = (junctionRows ?? []).map((r) => r.event_id as string);
    if (eventIds.length > 0) {
      const { data: directEvents } = await sb
        .from('events')
        .select('*')
        .in('id', eventIds.slice(0, 550))
        .order('event_time');
      events = ((directEvents ?? []) as Record<string, unknown>[]).map(mapEventRow);
    } else {
      events = [];
    }
  } else {
    events = ((eventRows ?? []) as Record<string, unknown>[]).map(mapEventRow);
  }

  return {
    id: inc.id,
    attackerIp: inc.attacker_ip,
    victimIp: inc.victim_ip,
    firstSeen: inc.first_seen,
    lastSeen: inc.last_seen,
    phasesDetected: inc.phases_detected,
    phaseCount: inc.phase_count,
    riskScore: inc.risk_score,
    severity: inc.severity,
    eventCount: inc.event_count,
    summary: inc.summary,
    status: (inc.status ?? 'new') as IncidentStatus,
    statusChangedAt: inc.status_changed_at,
    statusChangedBy: inc.status_changed_by,
    phaseBreakdown,
    events,
  };
}

export async function updateIncidentStatus(
  id: string,
  status: IncidentStatus,
  changedBy: string
): Promise<{ success: boolean; error?: string }> {
  const sb = createSupabaseAdminClient();

  const { error } = await sb
    .from('incidents')
    .update({
      status,
      status_changed_at: new Date().toISOString(),
      status_changed_by: changedBy,
    })
    .eq('id', id);

  if (error) return { success: false, error: error.message };
  return { success: true };
}

export async function deleteRun(
  runId: string
): Promise<{ success: boolean; error?: string }> {
  const sb = createSupabaseAdminClient();

  const { error } = await sb
    .from('correlation_runs')
    .delete()
    .eq('id', runId);

  if (error) return { success: false, error: error.message };
  return { success: true };
}

export async function getIncidentForReport(
  id: string
): Promise<{
  incident: IncidentDetail;
  allNonReconEvents: EventRow[];
} | null> {
  const incident = await getIncidentById(id);
  if (!incident) return null;

  const sb = createSupabaseAdminClient();
  const { data: eventRows, error: rpcError } = await sb.rpc('get_incident_events', {
    p_incident_id: id,
    max_non_recon: 1000,
    max_recon: 0,
  });

  let allNonReconEvents: EventRow[];
  if (rpcError) {
    const { data: junctionRows } = await sb
      .from('incident_events')
      .select('event_id')
      .eq('incident_id', id)
      .neq('phase', 'reconnaissance');

    const eventIds = (junctionRows ?? []).map((r) => r.event_id as string);
    if (eventIds.length > 0) {
      const { data: directEvents } = await sb
        .from('events')
        .select('*')
        .in('id', eventIds.slice(0, 1000))
        .order('event_time');
      allNonReconEvents = ((directEvents ?? []) as Record<string, unknown>[]).map(mapEventRow);
    } else {
      allNonReconEvents = [];
    }
  } else {
    allNonReconEvents = ((eventRows ?? []) as Record<string, unknown>[]).map(mapEventRow);
  }

  return { incident, allNonReconEvents };
}
