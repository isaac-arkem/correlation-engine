import { parse as csvParse } from 'csv-parse';
import { parse as parseDate, format } from 'date-fns';
import { createReadStream } from 'fs';
import { readFile } from 'fs/promises';
import { createInterface } from 'readline';
import type { NormalizedEvent } from './types';
import { getCorrelationConfig } from './config';

const SKIP_EVENT_TYPES = new Set(['stats']);

const INFRA_PORTS = new Set([445, 135, 139, 3389, 5985, 5986]);

function isAttackRelevantFlow(ev: Record<string, unknown>): boolean {
  const srcIp = ev.src_ip as string | undefined;
  const destIp = ev.dest_ip as string | undefined;
  const srcPort = ev.src_port as number | undefined;
  const destPort = ev.dest_port as number | undefined;

  const cfg = getCorrelationConfig();

  // Always keep flows on known C2 or infrastructure ports
  if (cfg.c2Ports.has(destPort ?? 0) || cfg.c2Ports.has(srcPort ?? 0)) return true;
  if (INFRA_PORTS.has(destPort ?? 0) || INFRA_PORTS.has(srcPort ?? 0)) return true;

  // For flows between known hosts, only keep scan probes
  const knownHosts = [...cfg.attackerIps, ...cfg.victimIps];
  if (knownHosts.includes(srcIp ?? '') && knownHosts.includes(destIp ?? '')) {
    const flow = ev.flow as Record<string, unknown> | undefined;
    const tcp = ev.tcp as Record<string, unknown> | undefined;
    const pktsToClient = (flow?.pkts_toclient as number) ?? 0;
    const pktsToServer = (flow?.pkts_toserver as number) ?? 0;
    const state = tcp?.state as string | undefined;

    if (state === 'syn_sent' && pktsToClient === 0) return true;
    if (state === 'closed' && pktsToServer <= 2 && pktsToClient <= 2) return true;

    return false;
  }

  return false;
}

function processSuricataRecord(
  ev: Record<string, unknown>,
  range: { from?: string; to?: string } | undefined,
): { event?: NormalizedEvent; skippedStat?: boolean; skippedFlow?: boolean } {
  const eventType = ev.event_type as string | undefined;
  if (!eventType || SKIP_EVENT_TYPES.has(eventType)) {
    return { skippedStat: true };
  }

  const timestamp = ev.timestamp as string;
  if (range?.from && timestamp < range.from) return {};
  if (range?.to && timestamp > range.to) return {};

  if (eventType === 'flow' && !isAttackRelevantFlow(ev)) {
    return { skippedFlow: true };
  }

  const alert = ev.alert as Record<string, unknown> | undefined;

  return {
    event: {
      source: 'suricata',
      eventTime: timestamp,
      eventType,
      srcIp: ev.src_ip as string | undefined,
      destIp: ev.dest_ip as string | undefined,
      srcPort: ev.src_port as number | undefined,
      destPort: ev.dest_port as number | undefined,
      proto: ev.proto as string | undefined,
      signature: alert?.signature as string | undefined,
      category: alert?.category as string | undefined,
      raw: ev,
    },
  };
}

export async function parseSuricataEve(
  filePath: string,
  range?: { from?: string; to?: string }
): Promise<NormalizedEvent[]> {
  const events: NormalizedEvent[] = [];
  let skippedStats = 0;
  let skippedFlows = 0;

  // Peek at the first non-empty character to decide format
  const head = await readFile(filePath, { encoding: 'utf-8', flag: 'r' });
  const trimmed = head.trimStart();

  if (trimmed.startsWith('[')) {
    // JSON array format
    let arr: Record<string, unknown>[];
    try {
      arr = JSON.parse(head);
    } catch {
      console.warn('[suricata] Failed to parse JSON array');
      return events;
    }

    for (const ev of arr) {
      const result = processSuricataRecord(ev, range);
      if (result.event) events.push(result.event);
      if (result.skippedStat) skippedStats++;
      if (result.skippedFlow) skippedFlows++;
    }

    console.log(
      `[suricata] ${arr.length} records in array, ${events.length} kept, ${skippedStats} stats skipped, ${skippedFlows} irrelevant flows skipped`
    );
  } else {
    // JSON lines format (one object per line)
    const rl = createInterface({
      input: createReadStream(filePath, { encoding: 'utf-8' }),
      crlfDelay: Infinity,
    });

    let lineCount = 0;
    for await (const line of rl) {
      lineCount++;
      if (!line.trim()) continue;

      let ev: Record<string, unknown>;
      try {
        ev = JSON.parse(line);
      } catch {
        continue;
      }

      const result = processSuricataRecord(ev, range);
      if (result.event) events.push(result.event);
      if (result.skippedStat) skippedStats++;
      if (result.skippedFlow) skippedFlows++;
    }

    console.log(
      `[suricata] ${lineCount} lines read, ${events.length} kept, ${skippedStats} stats skipped, ${skippedFlows} irrelevant flows skipped`
    );
  }

  return events;
}

function parseDDMMYYYY(dateStr: string): string {
  const cleaned = dateStr.trim();
  try {
    const parsed = parseDate(cleaned, 'dd/MM/yyyy HH:mm:ss', new Date());
    return format(parsed, "yyyy-MM-dd'T'HH:mm:ss");
  } catch {
    try {
      const parsed = parseDate(cleaned, 'dd/MM/yyyy HH:mm', new Date());
      return format(parsed, "yyyy-MM-dd'T'HH:mm:ss");
    } catch {
      return cleaned;
    }
  }
}

export async function parseWindowsSecurity(
  filePath: string,
  range?: { from?: string; to?: string }
): Promise<NormalizedEvent[]> {
  const events: NormalizedEvent[] = [];

  return new Promise((resolve, reject) => {
    const parser = csvParse({
      columns: (headers: string[]) => [...headers, 'Message'],
      bom: true,
      relax_column_count: true,
      skip_empty_lines: true,
    });

    let count = 0;

    const stream = createReadStream(filePath, { encoding: 'utf-8' }).pipe(parser);

    stream.on('data', (row: Record<string, string>) => {
      count++;
      const dateStr = row['Date and Time'];
      if (!dateStr) return;

      const eventTime = parseDDMMYYYY(dateStr);
      if (range?.from && eventTime < range.from) return;
      if (range?.to && eventTime > range.to) return;

      const eventId = parseInt(row['Event ID'], 10) || undefined;
      const message = row['Message'] || '';

      let srcIp: string | undefined;
      let accountName: string | undefined;
      let processName: string | undefined;

      const srcMatch = message.match(/Source Network Address:\s*([^\s\r\n]+)/);
      if (srcMatch) srcIp = srcMatch[1] === '-' ? undefined : srcMatch[1];

      const accMatch = message.match(/Account Name:\s*([^\s\r\n]+)/);
      if (accMatch) accountName = accMatch[1];

      const procMatch = message.match(/Process Name:\s*([^\s\r\n]+)/);
      if (procMatch) processName = procMatch[1];

      events.push({
        source: 'windows_security',
        eventTime,
        eventId,
        message: message.substring(0, 500),
        srcIp,
        category: row['Task Category'] || undefined,
        raw: {
          keywords: row['Keywords'],
          source: row['Source'],
          taskCategory: row['Task Category'],
          accountName,
          processName,
          message,
        },
      });
    });

    stream.on('end', () => {
      console.log(`[windows_security] ${count} rows parsed, ${events.length} kept`);
      resolve(events);
    });
    stream.on('error', reject);
  });
}

export async function parsePowerShell(
  filePath: string,
  range?: { from?: string; to?: string }
): Promise<NormalizedEvent[]> {
  const events: NormalizedEvent[] = [];

  return new Promise((resolve, reject) => {
    const parser = csvParse({
      columns: (headers: string[]) => [...headers, 'Message'],
      bom: true,
      relax_column_count: true,
      skip_empty_lines: true,
    });

    let count = 0;

    const stream = createReadStream(filePath, { encoding: 'utf-8' }).pipe(parser);

    stream.on('data', (row: Record<string, string>) => {
      count++;
      const dateStr = row['Date and Time'];
      if (!dateStr) return;

      const eventTime = parseDDMMYYYY(dateStr);
      if (range?.from && eventTime < range.from) return;
      if (range?.to && eventTime > range.to) return;

      const eventId = parseInt(row['Event ID'], 10) || undefined;
      const message = row['Message'] || '';

      events.push({
        source: 'powershell',
        eventTime,
        eventId,
        message: message.substring(0, 1000),
        category: row['Task Category'] || undefined,
        raw: {
          level: row['Level'],
          source: row['Source'],
          taskCategory: row['Task Category'],
          message,
        },
      });
    });

    stream.on('end', () => {
      console.log(`[powershell] ${count} rows parsed, ${events.length} kept`);
      resolve(events);
    });
    stream.on('error', reject);
  });
}
