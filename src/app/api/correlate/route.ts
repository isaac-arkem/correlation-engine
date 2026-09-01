import { NextResponse } from 'next/server';
import { writeFile, unlink, mkdir } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { randomUUID } from 'crypto';

import { createSupabaseServerClient } from '@/lib/supabase/server';
import { parseSuricataEve, parseWindowsSecurity, parsePowerShell } from '@/lib/correlation/parse';
import { classifyAll } from '@/lib/correlation/classify';
import { correlate } from '@/lib/correlation/correlate';
import {
  createRun,
  completeRun,
  failRun,
  persistEvents,
  persistIncidents,
} from '@/lib/correlation/persist';
import { autoDetectConfig } from '@/lib/correlation/auto-detect';
import { setCorrelationConfig, resetConfigCache } from '@/lib/correlation/config';
import type { NormalizedEvent } from '@/lib/correlation/types';
import type { LogType } from '@/lib/correlation/detect';

export const maxDuration = 60;

const PARSERS: Record<string, (path: string) => Promise<NormalizedEvent[]>> = {
  suricata: (p) => parseSuricataEve(p),
  windows_security: (p) => parseWindowsSecurity(p),
  powershell: (p) => parsePowerShell(p),
};

export async function POST(request: Request) {
  const supabase = await createSupabaseServerClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const formData = await request.formData();

  const label = formData.get('label') as string | null;
  if (!label?.trim()) {
    return NextResponse.json(
      { error: 'A dataset label is required' },
      { status: 400 }
    );
  }

  const files = formData.getAll('files') as File[];
  const types = formData.getAll('types') as string[];

  if (files.length === 0) {
    return NextResponse.json(
      { error: 'At least one log file is required' },
      { status: 400 }
    );
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      function send(data: Record<string, unknown>) {
        controller.enqueue(encoder.encode(JSON.stringify(data) + '\n'));
      }

      let runId: string | null = null;
      const tempDir = join(tmpdir(), `correlation-${randomUUID()}`);
      const tempFiles: string[] = [];

      try {
        await mkdir(tempDir, { recursive: true });

        const allEvents: NormalizedEvent[] = [];
        const fileCount = files.length;

        for (let i = 0; i < fileCount; i++) {
          const file = files[i];
          const logType = (types[i] ?? 'unknown') as LogType;
          const parser = PARSERS[logType];

          const pct = Math.round(5 + ((i + 1) / fileCount) * 30);
          send({
            step: 'parsing',
            message: `Parsing ${file.name}…`,
            file: file.name,
            fileIndex: i + 1,
            fileCount,
            progress: Math.round(5 + (i / fileCount) * 30),
          });

          if (!parser) {
            console.warn(`[correlate] Skipping unknown type: ${file.name} (${logType})`);
            continue;
          }

          const ext = file.name.split('.').pop() ?? 'dat';
          const tempPath = join(tempDir, `file_${i}.${ext}`);
          const buffer = Buffer.from(await file.arrayBuffer());
          await writeFile(tempPath, buffer);
          tempFiles.push(tempPath);

          const events = await parser(tempPath);
          allEvents.push(...events);

          send({
            step: 'parsed',
            message: `Parsed ${events.length.toLocaleString()} events from ${file.name}`,
            file: file.name,
            eventsParsed: events.length,
            progress: pct,
          });
        }

        if (allEvents.length === 0) {
          send({ step: 'error', message: 'No events found in the uploaded files', progress: 0 });
          controller.close();
          return;
        }

        allEvents.sort((a, b) => a.eventTime.localeCompare(b.eventTime));

        send({
          step: 'detecting',
          message: `Auto-detecting attacker/victim IPs from ${allEvents.length.toLocaleString()} events…`,
          totalEvents: allEvents.length,
          progress: 40,
        });

        resetConfigCache();
        const detectedConfig = autoDetectConfig(allEvents);
        setCorrelationConfig(detectedConfig);

        const attackerIps = detectedConfig.attackerIps;
        const victimIps = detectedConfig.victimIps;
        const c2Ports = [...detectedConfig.c2Ports];

        send({
          step: 'detected',
          message: 'Auto-detection complete',
          detected: { attackerIps, victimIps, c2Ports },
          progress: 48,
        });

        send({
          step: 'classifying',
          message: 'Classifying events into kill chain phases…',
          progress: 50,
        });

        classifyAll(allEvents);

        const classifiedEvents = allEvents.filter((e) => e.killChainPhase);
        send({
          step: 'classified',
          message: `${classifiedEvents.length.toLocaleString()} events classified across kill chain phases`,
          classifiedCount: classifiedEvents.length,
          progress: 60,
        });

        send({
          step: 'correlating',
          message: 'Correlating multi-stage incidents…',
          progress: 65,
        });

        const incidents = correlate(allEvents);

        send({
          step: 'correlated',
          message: `${incidents.length} incident${incidents.length !== 1 ? 's' : ''} detected`,
          incidentCount: incidents.length,
          progress: 72,
        });

        send({
          step: 'persisting',
          message: 'Creating run record…',
          progress: 75,
        });

        runId = await createRun({
          label: label.trim(),
          sourceType: 'file',
          attackerIps,
          victimIps,
          c2Ports,
        });

        send({
          step: 'persisting',
          message: `Saving ${classifiedEvents.length.toLocaleString()} events to database…`,
          progress: 80,
        });

        const eventIdMap = await persistEvents(classifiedEvents, runId);

        send({
          step: 'persisting',
          message: 'Saving incidents…',
          progress: 90,
        });

        await persistIncidents(incidents, eventIdMap, runId);
        await completeRun(runId, classifiedEvents, incidents.length);

        send({
          step: 'done',
          message: 'Correlation complete',
          progress: 100,
          result: {
            runId,
            label: label.trim(),
            eventCount: classifiedEvents.length,
            incidentCount: incidents.length,
          },
          detected: { attackerIps, victimIps, c2Ports },
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        if (runId) {
          await failRun(runId, message);
        }
        send({ step: 'error', message, progress: 0 });
      } finally {
        for (const path of tempFiles) {
          try { await unlink(path); } catch {}
        }
        try {
          const { rmdir } = await import('fs/promises');
          await rmdir(tempDir);
        } catch {}
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Transfer-Encoding': 'chunked',
      'Cache-Control': 'no-cache',
    },
  });
}
