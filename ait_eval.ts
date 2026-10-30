/**
 * ait_eval.ts — Evaluate the UNMODIFIED correlation engine against the
 * accredited AIT Log Data Set V1.1 (Austrian Institute of Technology).
 *
 * It reuses the engine's own parser, auto-detection, classifier, correlator
 * and ground-truth comparison — nothing in src/lib/correlation is changed.
 * The engine auto-detects attacker/victim/C2 ports from the logs, exactly
 * like the upload UI; no IPs are told to it.
 *
 * Usage:
 *   npx tsx ait_eval.ts <eve.json> [declaredAttackerIp declaredVictimIp] [expectedPhases csv]
 */
import { parseSuricataEve } from './src/lib/correlation/parse';
import { classifyAll } from './src/lib/correlation/classify';
import { correlate } from './src/lib/correlation/correlate';
import { setCorrelationConfig } from './src/lib/correlation/config';
import { autoDetectConfig } from './src/lib/correlation/auto-detect';
import { compareToGroundTruth, parseGroundTruth } from './src/lib/correlation/ground-truth';

async function main() {
  // gtAttacker/gtVictim are ONLY used to declare ground truth (from AIT's own
  // attack log). The engine itself auto-detects its IPs from the logs.
  const [evePath, gtAttacker, gtVictim, phasesCsv] = process.argv.slice(2);
  if (!evePath) {
    console.error('Usage: npx tsx ait_eval.ts <eve.json> [declaredAttackerIp declaredVictimIp] [expectedPhases]');
    process.exit(1);
  }
  const expectedPhases = (phasesCsv ?? 'reconnaissance,delivery')
    .split(',').map((s) => s.trim()).filter(Boolean);

  console.log(`\n=== AIT Log Data Set V1.1 — engine evaluation ===`);
  console.log(`eve.json : ${evePath}\n`);

  const events = await parseSuricataEve(evePath);

  // Auto-detect attacker / victim / C2 ports from the logs — same as the UI.
  const detected = autoDetectConfig(events);
  setCorrelationConfig(detected);

  classifyAll(events);

  const attackerIp = gtAttacker ?? detected.attackerIps[0];
  const victimIp = gtVictim ?? detected.victimIps[0];

  // Per-phase breakdown on the (auto-detected) primary pair
  const byPhase: Record<string, number> = {};
  for (const e of events) {
    if (!e.killChainPhase) continue;
    const onPair =
      (detected.attackerIps.includes(e.srcIp ?? '') && detected.victimIps.includes(e.destIp ?? '')) ||
      (detected.victimIps.includes(e.srcIp ?? '') && detected.attackerIps.includes(e.destIp ?? ''));
    if (onPair) byPhase[e.killChainPhase] = (byPhase[e.killChainPhase] ?? 0) + 1;
  }
  console.log('\nPhase distribution on the detected pair:');
  for (const [p, n] of Object.entries(byPhase)) console.log(`  ${p.padEnd(22)} ${n}`);

  const incidents = correlate(events);
  console.log(`\n--- Incidents emitted: ${incidents.length} ---`);
  for (const inc of incidents) {
    console.log(`\n  ${inc.attackerIp} -> ${inc.victimIp}`);
    console.log(`  phases   : ${inc.phasesDetected.join(' -> ')}`);
    console.log(`  events   : ${inc.eventCount}`);
    console.log(`  score    : ${inc.riskScore}  (${inc.severity})`);
    console.log(`  summary  : ${inc.summary}`);
  }

  // Ground-truth comparison (declared independently, before the run)
  if (attackerIp && victimIp) {
    const truth = parseGroundTruth({
      label: 'AIT Log Data Set V1.1 — declared ground truth',
      campaigns: [{ attackerIp, victimIp, expectedPhases, note: 'AIT Attack 1 multi-step: nmap/nikto scan + Horde webshell upload' }],
    });
    const cmp = compareToGroundTruth(
      truth,
      incidents.map((i) => ({ attackerIp: i.attackerIp, victimIp: i.victimIp, phases: i.phasesDetected })),
    );
    console.log(`\n--- Ground-truth comparison ---`);
    for (const c of cmp) {
      console.log(`  declared : ${c.campaign.attackerIp} -> ${c.campaign.victimIp}  [${c.campaign.expectedPhases.join(', ')}]`);
      console.log(`  found    : ${c.found ? 'YES' : 'NO'}`);
      console.log(`  detected : ${c.detectedPhases.join(', ') || '-'}`);
      console.log(`  missing  : ${c.missingPhases.join(', ') || '-'}`);
      console.log(`  extra    : ${c.unexpectedPhases.join(', ') || '-'}`);
    }
    const tp = cmp.filter((c) => c.found).length;
    console.log(`\n  recall (campaigns reconstructed): ${tp}/${cmp.length}`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
