import { NextResponse } from 'next/server';
import { createSupabaseAdminClient, createSupabaseServerClient } from '@/lib/supabase/server';
import { Client } from '@elastic/elasticsearch';
import { classifyAll } from '@/lib/correlation/classify';
import { correlate } from '@/lib/correlation/correlate';
import { persistEvents, persistIncidents } from '@/lib/correlation/persist';
import { autoDetectConfig } from '@/lib/correlation/auto-detect';
import { setCorrelationConfig, resetConfigCache } from '@/lib/correlation/config';
import type { NormalizedEvent } from '@/lib/correlation/types';
import { notifyLivePollEvent } from '@/lib/notifications/create';

function mapSuricataHit(s: Record<string, unknown>): NormalizedEvent {
  const alert = s.alert as Record<string, unknown> | undefined;
  return {
    source: 'suricata',
    eventTime: (s['@timestamp'] || s.timestamp) as string,
    eventType: s.event_type as string,
    srcIp: s.src_ip as string | undefined,
    destIp: s.dest_ip as string | undefined,
    srcPort: s.src_port as number | undefined,
    destPort: s.dest_port as number | undefined,
    proto: s.proto as string | undefined,
    signature: alert?.signature as string | undefined,
    category: alert?.category as string | undefined,
    raw: s,
  };
}

function mapWinlogHit(s: Record<string, unknown>): NormalizedEvent {
  const winlog = s.winlog as Record<string, unknown> | undefined;
  const eventData = winlog?.event_data as Record<string, unknown> | undefined;
  const eventObj = s.event as Record<string, unknown> | undefined;
  const eventCode = eventObj?.code as number | undefined;
  const isPS = eventCode === 4104;

  return {
    source: isPS ? 'powershell' : 'windows_security',
    eventTime: s['@timestamp'] as string,
    eventId: eventCode,
    srcIp: (eventData?.IpAddress || eventData?.SourceNetworkAddress) as string | undefined,
    message: ((s.message || eventData?.ScriptBlockText) as string)?.substring(0, 1000),
    category: winlog?.task as string | undefined,
    raw: s,
  };
}

export const maxDuration = 60;

export async function POST(request: Request) {
  const supabase = await createSupabaseServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body: { runId: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const { runId } = body;
  if (!runId) {
    return NextResponse.json({ error: 'runId is required' }, { status: 400 });
  }

  // Look up the run and its linked connection
  const { data: run } = await supabase
    .from('correlation_runs')
    .select('id, connection_id, poll_count, last_poll_at, status')
    .eq('id', runId)
    .single();

  if (!run) {
    return NextResponse.json({ error: 'Run not found' }, { status: 404 });
  }
  if (run.status === 'completed') {
    return NextResponse.json({ error: 'Run already completed' }, { status: 400 });
  }
  if (!run.connection_id) {
    return NextResponse.json({ error: 'Run has no linked connection' }, { status: 400 });
  }

  const { data: conn } = await supabase
    .from('es_connections')
    .select('*')
    .eq('id', run.connection_id)
    .single();

  if (!conn) {
    return NextResponse.json({ error: 'Connection not found' }, { status: 404 });
  }

  // Build ES client from saved connection
  const clientOpts: Record<string, unknown> = {};
  if (conn.cloud_id) {
    clientOpts.cloud = { id: conn.cloud_id };
  } else if (conn.es_url) {
    clientOpts.node = conn.es_url;
  } else {
    return NextResponse.json({ error: 'Connection has no URL or Cloud ID' }, { status: 400 });
  }
  if (conn.api_key) {
    clientOpts.auth = { apiKey: conn.api_key };
  }

  // Determine the "since" timestamp — use last_poll_at or 5 min ago
  const since = run.last_poll_at ?? new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const admin = createSupabaseAdminClient();
  const pollInterval = conn.poll_interval ?? 30;

  let client: Client | undefined;
  try {
    client = new Client({
      ...(clientOpts as ConstructorParameters<typeof Client>[0]),
      requestTimeout: 20_000,
      maxRetries: 1,
    });
    const rangeFilter = { range: { '@timestamp': { gt: since } } };

    // Query Suricata
    const suricataResp = await client.search({
      index: conn.suricata_index,
      size: 10000,
      query: {
        bool: {
          must: [
            rangeFilter,
            {
              bool: {
                should: [
                  { term: { event_type: 'alert' } },
                  { term: { event_type: 'http' } },
                  { term: { event_type: 'flow' } },
                  { term: { event_type: 'smb' } },
                  { term: { event_type: 'anomaly' } },
                ],
                minimum_should_match: 1,
              },
            },
          ],
        },
      },
      sort: [{ '@timestamp': 'asc' }],
    });

    const suricataHits = (suricataResp.hits.hits as Array<{ _source: Record<string, unknown> }>)
      .map((h) => mapSuricataHit(h._source));

    // Query Winlogbeat
    let winlogHits: NormalizedEvent[] = [];
    try {
      const winlogResp = await client.search({
        index: conn.winlog_index,
        size: 10000,
        query: {
          bool: {
            must: [
              rangeFilter,
              {
                bool: {
                  should: [
                    { term: { 'event.code': 4104 } },
                    { term: { 'event.code': 4624 } },
                    { term: { 'event.code': 4625 } },
                    { term: { 'event.code': 4798 } },
                  ],
                  minimum_should_match: 1,
                },
              },
            ],
          },
        },
        sort: [{ '@timestamp': 'asc' }],
      });
      winlogHits = (winlogResp.hits.hits as Array<{ _source: Record<string, unknown> }>)
        .map((h) => mapWinlogHit(h._source));
    } catch {
      // winlogbeat index may not exist
    }

    const newEvents = [...suricataHits, ...winlogHits];
    newEvents.sort((a, b) => a.eventTime.localeCompare(b.eventTime));

    const lastTimestamp = newEvents.length > 0
      ? newEvents[newEvents.length - 1].eventTime
      : new Date().toISOString();

    // RLS on correlation_runs is SELECT-only for authenticated users —
    // writes must go through the service-role client or poll_count never sticks.
    const newPollCount = (run.poll_count ?? 0) + 1;
    const { error: pollErr } = await admin.from('correlation_runs').update({
      poll_count: newPollCount,
      last_poll_at: lastTimestamp,
    }).eq('id', runId);

    if (pollErr) {
      console.error('[live/poll] failed to persist poll_count:', pollErr.message);
    }

    if (newEvents.length === 0) {
      const { data: totals } = await admin
        .from('correlation_runs')
        .select('event_count, incident_count')
        .eq('id', runId)
        .single();

      return NextResponse.json({
        newEvents: 0,
        totalEvents: totals?.event_count ?? 0,
        incidentCount: totals?.incident_count ?? 0,
        lastTimestamp,
        pollCount: newPollCount,
        maxPolls: conn.max_polls,
        pollInterval,
      });
    }

    // Classify and correlate
    resetConfigCache();
    const detectedConfig = autoDetectConfig(newEvents);
    setCorrelationConfig(detectedConfig);
    classifyAll(newEvents);

    const classified = newEvents.filter((e) => e.killChainPhase);
    const incidents = correlate(newEvents);

    // Persist
    const eventIdMap = await persistEvents(classified, runId);
    await persistIncidents(incidents, eventIdMap, runId);

    const { count: eventCount } = await admin
      .from('events')
      .select('id', { count: 'exact', head: true })
      .eq('run_id', runId);

    const { count: incidentCount } = await admin
      .from('incidents')
      .select('id', { count: 'exact', head: true })
      .eq('run_id', runId);

    // Build source/phase counts from all events in this run
    const { data: allEvts } = await admin
      .from('events')
      .select('source, kill_chain_phase')
      .eq('run_id', runId)
      .limit(10000);

    const sourceCounts: Record<string, number> = {};
    const phaseCounts: Record<string, number> = {};
    for (const ev of allEvts ?? []) {
      if (ev.source) sourceCounts[ev.source] = (sourceCounts[ev.source] ?? 0) + 1;
      if (ev.kill_chain_phase) phaseCounts[ev.kill_chain_phase] = (phaseCounts[ev.kill_chain_phase] ?? 0) + 1;
    }

    await admin.from('correlation_runs').update({
      event_count: eventCount ?? 0,
      incident_count: incidentCount ?? 0,
      source_counts: sourceCounts,
      phase_counts: phaseCounts,
      attacker_ips: detectedConfig.attackerIps,
      victim_ips: detectedConfig.victimIps,
      c2_ports: [...detectedConfig.c2Ports],
    }).eq('id', runId);

    await notifyLivePollEvent(user.id, conn.label, newEvents.length, eventCount ?? 0, runId);

    return NextResponse.json({
      newEvents: newEvents.length,
      classifiedEvents: classified.length,
      totalEvents: eventCount ?? 0,
      incidentCount: incidentCount ?? 0,
      lastTimestamp,
      pollCount: newPollCount,
      maxPolls: conn.max_polls,
      pollInterval,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Poll failed';
    return NextResponse.json({ error: msg }, { status: 500 });
  } finally {
    await client?.close().catch(() => undefined);
  }
}
