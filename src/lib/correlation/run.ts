/**
 * run.ts — Orchestration script for the correlation engine.
 *
 * Usage: npx tsx src/lib/correlation/run.ts [--label "My Run"]
 *                                          [--ground-truth path/to/truth.json]
 *                                          [--from 2026-05-01] [--to 2026-07-31]
 *
 * --from/--to bound the ANALYSIS WINDOW. Events outside it are dropped at
 * parse time, before classification, so the window is applied consistently
 * across all three sources. The bounds are recorded in the run label and
 * printed in the summary so a scoped run is never mistaken for a full one.
 *
 * A ground-truth file declares the campaigns that are actually present in
 * the data, independently of what the engine finds. When supplied, the run
 * prints a detection report against it and stores it on the run record so
 * the evaluation page can compute non-circular precision and recall.
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
import { setCorrelationConfig, resetConfigCache, type CorrelationConfig } from './config';
import { autoDetectConfig } from './auto-detect';
import { loadGroundTruth, compareToGroundTruth, type GroundTruth } from './ground-truth';

function parseArgs(): {
  label: string;
  groundTruthPath?: string;
  from?: string;
  to?: string;
  declared?: CorrelationConfig;
} {
  const args = process.argv.slice(2);
  const labelIdx = args.indexOf('--label');
  const label =
    labelIdx !== -1 && args[labelIdx + 1]
      ? args[labelIdx + 1]
      : `CLI Run — ${new Date().toISOString().slice(0, 16)}`;

  const gtIdx = args.indexOf('--ground-truth');
  const groundTruthPath =
    gtIdx !== -1 && args[gtIdx + 1]
      ? args[gtIdx + 1]
      : process.env.GROUND_TRUTH_PATH || undefined;

  const fromIdx = args.indexOf('--from');
  const toIdx = args.indexOf('--to');
  const from = fromIdx !== -1 && args[fromIdx + 1] ? args[fromIdx + 1] : undefined;
  const to = toIdx !== -1 && args[toIdx + 1] ? args[toIdx + 1] : undefined;

  // --attacker/--victim/--c2-ports declare the hosts under study instead of
  // auto-detecting them. Auto-detect ranks IPs by Suricata alert volume, so
  // routine noise (e.g. APT package-update alerts) can outrank the real attack.
  const list = (flag: string) => {
    const i = args.indexOf(flag);
    return i !== -1 && args[i + 1] ? args[i + 1].split(',').map((s) => s.trim()).filter(Boolean) : undefined;
  };
  const attackerIps = list('--attacker');
  const victimIps = list('--victim');
  const c2Ports = list('--c2-ports');
  if (!!attackerIps !== !!victimIps) {
    console.error('--attacker and --victim must be given together');
    process.exit(1);
  }
  const declared = attackerIps && victimIps
    ? { attackerIps, victimIps, c2Ports: new Set((c2Ports ?? []).map(Number)) }
    : undefined;

  return { label, groundTruthPath, from, to, declared };
}

/**
 * Expand a bare date to a full-day bound so `--from 2026-05-01 --to 2026-07-31`
 * means the whole of 1 May through the whole of 31 July, not midnight to
 * midnight (which would silently drop the last day).
 */
function normaliseBound(value: string | undefined, end: boolean): string | undefined {
  if (!value) return undefined;
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return end ? `${value}T23:59:59.999999` : `${value}T00:00:00.000000`;
  }
  return value;
}

async function main() {
  const { label, groundTruthPath, from: rawFrom, to: rawTo, declared } = parseArgs();

  const from = normaliseBound(rawFrom, false);
  const to = normaliseBound(rawTo, true);
  const range = from || to ? { from, to } : undefined;

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

  // Loaded up front: a malformed answer key should abort before a long run,
  // not after it.
  let groundTruth: GroundTruth | null = null;
  if (groundTruthPath) {
    groundTruth = await loadGroundTruth(groundTruthPath);
  }

  console.log('=== CORRELATION ENGINE — RUN SUMMARY ===\n');
  console.log(`Label: ${label}`);
  console.log('Source: FileSource (demo mode)');
  console.log(
    range
      ? `Analysis window: ${from ?? '(open)'} → ${to ?? '(open)'}`
      : 'Analysis window: none — the full capture is processed',
  );
  console.log(
    groundTruth
      ? `Ground truth: ${groundTruth.campaigns.length} declared campaigns (${groundTruthPath})\n`
      : 'Ground truth: none declared — evaluation will fall back to the derived method\n',
  );

  try {
    // Step 1: Ingest
    console.log('--- STEP 1: INGESTION ---');
    const source = new FileSource({
      evePath,
      winSecurityPath: winSecPath,
      psOperationalPath: psPath,
    });

    const startTime = Date.now();
    const events = await source.getSecurityEvents(range);
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

    // Declared attacker/victim IPs and C2 ports, or auto-detected ones
    resetConfigCache();
    const cfg = declared ?? autoDetectConfig(events);
    console.log(
      `Hosts: ${declared ? 'declared' : 'auto-detected'} — attackers ${cfg.attackerIps.join(', ')}; ` +
        `victims ${cfg.victimIps.join(', ')}; C2 ports ${[...cfg.c2Ports].join(', ') || 'none'}\n`,
    );
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

    // Detection report against the declared ground truth
    if (groundTruth) {
      console.log('--- GROUND TRUTH COMPARISON ---');
      const comparisons = compareToGroundTruth(
        groundTruth,
        incidents.map((i) => ({
          attackerIp: i.attackerIp,
          victimIp: i.victimIp,
          phases: i.phasesDetected,
        })),
      );

      for (const cmp of comparisons) {
        const { campaign } = cmp;
        const mark = cmp.found ? (cmp.missingPhases.length ? 'PARTIAL' : 'FOUND  ') : 'MISSED ';
        console.log(`  [${mark}] ${campaign.attackerIp} → ${campaign.victimIp}`);
        console.log(`    Expected: ${campaign.expectedPhases.join(', ')}`);
        console.log(`    Detected: ${cmp.detectedPhases.join(', ') || '(none)'}`);
        if (cmp.missingPhases.length) {
          console.log(`    MISSING:  ${cmp.missingPhases.join(', ')}`);
        }
        if (cmp.unexpectedPhases.length) {
          console.log(`    EXTRA:    ${cmp.unexpectedPhases.join(', ')}`);
        }
      }

      const tp = comparisons.filter((c) => c.found).length;
      const fn = comparisons.length - tp;
      const declaredPairs = new Set(
        comparisons.map((c) => [c.campaign.attackerIp, c.campaign.victimIp].sort().join('|')),
      );
      const fp = incidents.filter(
        (i) => !declaredPairs.has([i.attackerIp, i.victimIp].sort().join('|')),
      ).length;

      const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
      const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
      const f1 =
        precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

      console.log();
      console.log(`  TP: ${tp}   FP: ${fp}   FN: ${fn}`);
      console.log(
        `  Precision: ${precision.toFixed(3)}   Recall: ${recall.toFixed(3)}   F1: ${f1.toFixed(3)}`,
      );
      console.log(
        `  (measured against ${comparisons.length} declared campaigns — not self-derived)`,
      );
      console.log();
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
        groundTruth,
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
