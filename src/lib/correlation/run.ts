/**
 * run.ts — Orchestration script for the correlation engine.
 *
 * Usage: npx tsx src/lib/correlation/run.ts [--label "My Run"]
 *
 * Picks the event source (FileSource for demo), ingests all events,
 * classifies each into a kill-chain phase, correlates multi-stage
 * incidents, and persists to Supabase tagged with a run ID.
 */

import { config } from 'dotenv';
import { resolve } from 'path';

config({ path: resolve(process.cwd(), '.env.local') });

import { FileSource } from './sources/fileSource';
import { classifyAll } from './classify';
import { correlate } from './correlate';
import { createRun, completeRun, failRun, persistEvents, persistIncidents } from './persist';
import { setCorrelationConfig, resetConfigCache } from './config';
import { autoDetectConfig } from './auto-detect';

function parseArgs(): { label: string } {
  const args = process.argv.slice(2);
  const labelIdx = args.indexOf('--label');
  const label =
    labelIdx !== -1 && args[labelIdx + 1]
      ? args[labelIdx + 1]
      : `CLI Run — ${new Date().toISOString().slice(0, 16)}`;
  return { label };
}

async function main() {
  const { label } = parseArgs();

  const evePath = process.env.EVE_JSON_PATH;
  const winSecPath = process.env.WIN_SECURITY_CSV_PATH;
  const psPath = process.env.PS_OPERATIONAL_CSV_PATH;

  if (!evePath || !winSecPath || !psPath) {
    console.error(
      'Missing env vars: EVE_JSON_PATH, WIN_SECURITY_CSV_PATH, PS_OPERATIONAL_CSV_PATH'
    );
    process.exit(1);
  }

  let runId: string | null = null;

  console.log('=== CORRELATION ENGINE — RUN SUMMARY ===\n');
  console.log(`Label: ${label}`);
  console.log('Source: FileSource (demo mode)\n');

  try {
    // Step 1: Ingest
    console.log('--- STEP 1: INGESTION ---');
    const source = new FileSource({
      evePath,
      winSecurityPath: winSecPath,
      psOperationalPath: psPath,
    });

    const startTime = Date.now();
    const events = await source.getSecurityEvents();
    const ingestTime = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`Ingestion completed in ${ingestTime}s\n`);

    // Per-source stats
    const bySrc = { suricata: 0, windows_security: 0, powershell: 0 };
    const timestamps: Record<string, { min: string; max: string }> = {};

    for (const ev of events) {
      bySrc[ev.source]++;
      const ts = timestamps[ev.source];
      if (!ts) {
        timestamps[ev.source] = { min: ev.eventTime, max: ev.eventTime };
      } else {
        if (ev.eventTime < ts.min) ts.min = ev.eventTime;
        if (ev.eventTime > ts.max) ts.max = ev.eventTime;
      }
    }

    console.log('Events per source:');
    for (const [src, count] of Object.entries(bySrc)) {
      const ts = timestamps[src];
      if (ts) {
        console.log(`  ${src}: ${count} events (${ts.min} → ${ts.max})`);
      } else {
        console.log(`  ${src}: ${count} events`);
      }
    }
    console.log();

    // Auto-detect attacker/victim IPs and C2 ports
    resetConfigCache();
    const cfg = autoDetectConfig(events);
    setCorrelationConfig(cfg);

    // Step 2: Classify
    console.log('--- STEP 2: CLASSIFICATION ---');
    classifyAll(events);

    const phaseCounts: Record<string, number> = {};
    let unclassified = 0;
    for (const ev of events) {
      if (ev.killChainPhase) {
        phaseCounts[ev.killChainPhase] = (phaseCounts[ev.killChainPhase] ?? 0) + 1;
      } else {
        unclassified++;
      }
    }
    console.log('Phase breakdown:');
    for (const [phase, count] of Object.entries(phaseCounts).sort(
      (a, b) => b[1] - a[1]
    )) {
      console.log(`  ${phase}: ${count}`);
    }
    console.log(`  (unclassified): ${unclassified}`);
    console.log();

    // Step 3: Correlate
    console.log('--- STEP 3: CORRELATION ---');
    const incidents = correlate(events);
    console.log();

    // Summary
    console.log('--- INCIDENTS ---');
    if (incidents.length === 0) {
      console.log('  No multi-stage incidents detected.');
    } else {
      for (const inc of incidents) {
        console.log(`  INCIDENT: ${inc.attackerIp} → ${inc.victimIp}`);
        console.log(`    Severity:  ${inc.severity.toUpperCase()} (score: ${inc.riskScore})`);
        console.log(`    Phases:    ${inc.phasesDetected.join(' → ')}`);
        console.log(`    Events:    ${inc.eventCount}`);
        console.log(`    Window:    ${inc.firstSeen} → ${inc.lastSeen}`);
        console.log(`    Summary:   ${inc.summary}`);
        console.log();
      }
    }

    // Step 4: Persist to Supabase (if service role key is set)
    if (process.env.SUPABASE_SERVICE_ROLE_KEY) {
      console.log('--- STEP 4: PERSISTENCE ---');

      runId = await createRun({
        label,
        sourceType: 'file',
        attackerIps: cfg.attackerIps,
        victimIps: cfg.victimIps,
        c2Ports: [...cfg.c2Ports],
      });

      const classifiedEvents = events.filter((e) => e.killChainPhase);
      const eventIdMap = await persistEvents(classifiedEvents, runId);
      await persistIncidents(incidents, eventIdMap, runId);
      await completeRun(runId, classifiedEvents, incidents.length);
      console.log();
    } else {
      console.log('--- STEP 4: PERSISTENCE (skipped) ---');
      console.log('  SUPABASE_SERVICE_ROLE_KEY not set — skipping Supabase persistence.');
      console.log('  Add the key to .env.local and re-run to populate the database.\n');
    }

    console.log('=== RUN COMPLETE ===');
  } catch (err) {
    if (runId) {
      await failRun(runId, err instanceof Error ? err.message : 'Unknown error');
    }
    throw err;
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
