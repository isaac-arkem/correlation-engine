import { Client } from '@elastic/elasticsearch';
import type { EventSource, NormalizedEvent } from '../types';

/**
 * LiveDemoSource — reads the `live-demo` index populated by the viva replay
 * (demo_replay.py) and maps each document to a NormalizedEvent, the same shape
 * FileSource produces. Used for the end-to-end live demonstration so the engine
 * correlates exactly the events that were just streamed into Elasticsearch and
 * detected by the Kibana rules. Selected with `--source live-demo`.
 */
export class LiveDemoSource implements EventSource {
  private client: Client;
  private index: string;

  constructor(config: { node: string; apiKey?: string; username?: string; password?: string; index?: string }) {
    this.client = new Client({
      node: config.node,
      ...(config.apiKey
        ? { auth: { apiKey: config.apiKey } }
        : config.username && config.password
          ? { auth: { username: config.username, password: config.password } }
          : {}),
    });
    this.index = config.index ?? 'live-demo';
  }

  async getSecurityEvents(): Promise<NormalizedEvent[]> {
    const resp = await this.client.search({
      index: this.index,
      size: 10000,
      sort: [{ '@timestamp': 'asc' }],
      query: { match_all: {} },
    });

    const events = (resp.hits.hits as Array<{ _source: Record<string, unknown> }>)
      .map((h) => this.map(h._source))
      .filter((e): e is NormalizedEvent => e !== null);

    events.sort((a, b) => a.eventTime.localeCompare(b.eventTime));
    console.log(`[LiveDemoSource] Total: ${events.length} events from '${this.index}'`);
    return events;
  }

  private map(s: Record<string, unknown>): NormalizedEvent | null {
    const time = (s['@timestamp'] as string) ?? '';
    const event = (s.event as Record<string, unknown>) ?? {};
    const dataset = event.dataset as string | undefined;

    // Suricata: the original eve record is stored under suricata.eve
    const sur = s.suricata as Record<string, unknown> | undefined;
    if (dataset === 'suricata.eve' && sur?.eve) {
      const eve = sur.eve as Record<string, unknown>;
      const alert = eve.alert as Record<string, unknown> | undefined;
      return {
        source: 'suricata',
        eventTime: time,
        eventType: eve.event_type as string,
        srcIp: eve.src_ip as string | undefined,
        destIp: eve.dest_ip as string | undefined,
        srcPort: eve.src_port as number | undefined,
        destPort: eve.dest_port as number | undefined,
        proto: eve.proto as string | undefined,
        signature: alert?.signature as string | undefined,
        category: alert?.category as string | undefined,
        raw: eve,
      };
    }

    // Windows / PowerShell
    const code = parseInt((event.code as string) ?? '', 10);
    if (dataset === 'windows.powershell_operational' || code === 4104) {
      const ps = s.powershell as Record<string, unknown> | undefined;
      const file = ps?.file as Record<string, unknown> | undefined;
      return {
        source: 'powershell',
        eventTime: time,
        eventId: 4104,
        message: ((file?.script_block_text || s.message) as string)?.substring(0, 1000),
        raw: s,
      };
    }
    if (dataset === 'windows.security' || !Number.isNaN(code)) {
      const winlog = s.winlog as Record<string, unknown> | undefined;
      const ed = (winlog?.event_data as Record<string, unknown>) ?? {};
      return {
        source: 'windows_security',
        eventTime: time,
        eventId: Number.isNaN(code) ? undefined : code,
        srcIp: (ed['Network Information.Source Network Address'] || ed.IpAddress) as string | undefined,
        message: (s.message as string)?.substring(0, 1000),
        raw: s,
      };
    }
    return null;
  }
}
