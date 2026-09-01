import { Client } from '@elastic/elasticsearch';
import type { EventSource, NormalizedEvent } from '../types';

/**
 * ElasticsearchSource — the designed architecture path.
 *
 * Queries filebeat-* and winlogbeat-* indices for security-relevant events
 * and maps them to NormalizedEvent[], the same shape FileSource produces.
 * Selectable via CORRELATION_SOURCE=elasticsearch env var.
 */
export class ElasticsearchSource implements EventSource {
  private client: Client;

  constructor(config: { node: string; apiKey?: string }) {
    this.client = new Client({
      node: config.node,
      ...(config.apiKey ? { auth: { apiKey: config.apiKey } } : {}),
    });
  }

  async getSecurityEvents(
    range?: { from?: string; to?: string }
  ): Promise<NormalizedEvent[]> {
    const events: NormalizedEvent[] = [];

    const suricataEvents = await this.querySuricata(range);
    events.push(...suricataEvents);

    const winlogEvents = await this.queryWinlogbeat(range);
    events.push(...winlogEvents);

    events.sort((a, b) => a.eventTime.localeCompare(b.eventTime));

    console.log(
      `[ElasticsearchSource] Total: ${events.length} events (suricata: ${suricataEvents.length}, winlogbeat: ${winlogEvents.length})`
    );

    return events;
  }

  private async querySuricata(
    range?: { from?: string; to?: string }
  ): Promise<NormalizedEvent[]> {
    const musts: Record<string, unknown>[] = [
      {
        bool: {
          should: [
            { term: { 'event_type': 'alert' } },
            { term: { 'event_type': 'http' } },
            { term: { 'event_type': 'smb' } },
            { term: { 'event_type': 'ssh' } },
            { term: { 'event_type': 'anomaly' } },
            {
              bool: {
                must: [{ term: { 'event_type': 'flow' } }],
                should: [
                  { term: { 'dest_port': 4444 } },
                  { term: { 'dest_port': 5555 } },
                  { term: { 'src_port': 4444 } },
                  { term: { 'src_port': 5555 } },
                ],
                minimum_should_match: 1,
              },
            },
          ],
          minimum_should_match: 1,
        },
      },
    ];

    if (range?.from || range?.to) {
      const rangeQuery: Record<string, string> = {};
      if (range.from) rangeQuery.gte = range.from;
      if (range.to) rangeQuery.lte = range.to;
      musts.push({ range: { '@timestamp': rangeQuery } });
    }

    const resp = await this.client.search({
      index: 'filebeat-*',
      size: 10000,
      query: { bool: { must: musts } },
    });

    return (resp.hits.hits as Array<{ _source: Record<string, unknown> }>).map(
      (hit) => {
        const s = hit._source;
        const alert = s.alert as Record<string, unknown> | undefined;
        return {
          source: 'suricata' as const,
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
    );
  }

  private async queryWinlogbeat(
    range?: { from?: string; to?: string }
  ): Promise<NormalizedEvent[]> {
    const musts: Record<string, unknown>[] = [
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
    ];

    if (range?.from || range?.to) {
      const rangeQuery: Record<string, string> = {};
      if (range.from) rangeQuery.gte = range.from;
      if (range.to) rangeQuery.lte = range.to;
      musts.push({ range: { '@timestamp': rangeQuery } });
    }

    const resp = await this.client.search({
      index: 'winlogbeat-*',
      size: 10000,
      query: { bool: { must: musts } },
    });

    return (resp.hits.hits as Array<{ _source: Record<string, unknown> }>).map(
      (hit) => {
        const s = hit._source;
        const winlog = s.winlog as Record<string, unknown> | undefined;
        const eventData = winlog?.event_data as Record<string, unknown> | undefined;
        const eventObj = s.event as Record<string, unknown> | undefined;
        const eventCode = eventObj?.code as number | undefined;

        const isPS = eventCode === 4104;

        return {
          source: (isPS ? 'powershell' : 'windows_security') as
            | 'powershell'
            | 'windows_security',
          eventTime: s['@timestamp'] as string,
          eventId: eventCode,
          srcIp: (eventData?.IpAddress || eventData?.SourceNetworkAddress) as
            | string
            | undefined,
          message: ((s.message || eventData?.ScriptBlockText) as string)?.substring(
            0,
            1000
          ),
          category: winlog?.task as string | undefined,
          raw: s,
        };
      }
    );
  }
}
