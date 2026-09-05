import { readFile } from 'fs/promises';

import { normalizePhase, sortPhases } from './phase-vocab';

/**
 * ground-truth.ts — declared (external) ground truth for evaluation.
 *
 * WHY THIS EXISTS
 * ---------------
 * The evaluation view originally derived its own ground truth by re-reading
 * the events the engine had already classified and asking "which pairs span
 * two or more phases?". That is circular: a classification mistake is copied
 * into the answer key, so the engine is rewarded for reproducing its own
 * error, and a campaign the classifier missed *entirely* never appears in the
 * answer key at all — it is silently excluded from recall instead of counting
 * as a false negative.
 *
 * A declared ground truth breaks the circle. The expected campaigns are
 * written down independently of any run — by the operator who staged the
 * attack, or emitted by the synthetic lab generator that constructed it — and
 * the engine is then measured against that fixed list.
 *
 * This makes two previously invisible failure modes measurable:
 *   1. A campaign that produced no incident at all      → a true false negative.
 *   2. A campaign found, but with phases missing        → partial reconstruction.
 */

export interface GroundTruthCampaign {
  attackerIp: string;
  victimIp: string;
  /** Phases the operator asserts are present in this campaign. */
  expectedPhases: string[];
  /** Optional free-text provenance, e.g. "nmap -sS then msfvenom beacon". */
  note?: string;
}

export interface GroundTruth {
  label?: string;
  campaigns: GroundTruthCampaign[];
}

export class GroundTruthError extends Error {}

const IP_RE = /^[0-9a-fA-F.:]+$/;

function fail(msg: string): never {
  throw new GroundTruthError(`Invalid ground truth: ${msg}`);
}

/**
 * Validate and canonicalise a parsed ground-truth document.
 *
 * Strict by design — a silently malformed answer key would corrupt every
 * metric derived from it, so every problem is raised loudly instead.
 */
export function parseGroundTruth(input: unknown): GroundTruth {
  if (!input || typeof input !== 'object') fail('expected a JSON object');

  const doc = input as Record<string, unknown>;
  const rawCampaigns = doc.campaigns;

  if (!Array.isArray(rawCampaigns)) fail('"campaigns" must be an array');
  if (rawCampaigns.length === 0) fail('"campaigns" is empty');

  const seen = new Set<string>();
  const campaigns: GroundTruthCampaign[] = rawCampaigns.map((raw, i) => {
    const at = `campaigns[${i}]`;
    if (!raw || typeof raw !== 'object') fail(`${at} is not an object`);

    const c = raw as Record<string, unknown>;
    const attackerIp = typeof c.attackerIp === 'string' ? c.attackerIp.trim() : '';
    const victimIp = typeof c.victimIp === 'string' ? c.victimIp.trim() : '';

    if (!attackerIp) fail(`${at}.attackerIp is missing`);
    if (!victimIp) fail(`${at}.victimIp is missing`);
    if (!IP_RE.test(attackerIp)) fail(`${at}.attackerIp "${attackerIp}" is not an IP`);
    if (!IP_RE.test(victimIp)) fail(`${at}.victimIp "${victimIp}" is not an IP`);
    if (attackerIp === victimIp) fail(`${at} has the same attacker and victim`);

    if (!Array.isArray(c.expectedPhases) || c.expectedPhases.length === 0) {
      fail(`${at}.expectedPhases must be a non-empty array`);
    }

    const phases = sortPhases([
      ...new Set(
        (c.expectedPhases as unknown[]).map((p, j) => {
          if (typeof p !== 'string') fail(`${at}.expectedPhases[${j}] is not a string`);
          const norm = normalizePhase(p);
          if (!norm) fail(`${at}.expectedPhases[${j}] is empty`);
          return norm;
        }),
      ),
    ]);

    // Direction-insensitive duplicate check: a campaign declared twice would
    // be double-counted in both the numerator and denominator of recall.
    const key = [attackerIp, victimIp].sort().join('|');
    if (seen.has(key)) fail(`${at} duplicates an earlier campaign for this pair`);
    seen.add(key);

    return {
      attackerIp,
      victimIp,
      expectedPhases: phases,
      ...(typeof c.note === 'string' && c.note.trim() ? { note: c.note.trim() } : {}),
    };
  });

  return {
    ...(typeof doc.label === 'string' && doc.label.trim()
      ? { label: doc.label.trim() }
      : {}),
    campaigns,
  };
}

export async function loadGroundTruth(filePath: string): Promise<GroundTruth> {
  let text: string;
  try {
    text = await readFile(filePath, 'utf-8');
  } catch {
    throw new GroundTruthError(`Could not read ground-truth file: ${filePath}`);
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (err) {
    throw new GroundTruthError(
      `Ground-truth file is not valid JSON (${filePath}): ${
        err instanceof Error ? err.message : 'parse error'
      }`,
    );
  }

  return parseGroundTruth(json);
}

/** True when two pairs describe the same campaign in either direction. */
export function samePair(
  a1: string,
  v1: string,
  a2: string,
  v2: string,
): boolean {
  return (a1 === a2 && v1 === v2) || (a1 === v2 && v1 === a2);
}

export interface CampaignComparison {
  campaign: GroundTruthCampaign;
  /** An emitted incident matched this campaign. */
  found: boolean;
  detectedPhases: string[];
  /** Declared but not detected — the classifier's blind spots. */
  missingPhases: string[];
  /** Detected but not declared — over-classification. */
  unexpectedPhases: string[];
}

/**
 * Compare declared campaigns against what the engine actually emitted.
 *
 * `detected` is whatever the run produced: incident rows, or in-memory
 * Incident objects. Only the pair and its phases are needed.
 */
export function compareToGroundTruth(
  truth: GroundTruth,
  detected: Array<{ attackerIp: string; victimIp: string; phases: string[] }>,
): CampaignComparison[] {
  return truth.campaigns.map((campaign) => {
    const hit = detected.find((d) =>
      samePair(campaign.attackerIp, campaign.victimIp, d.attackerIp, d.victimIp),
    );

    const detectedPhases = sortPhases([
      ...new Set(
        (hit?.phases ?? [])
          .map((p) => normalizePhase(p))
          .filter((p): p is string => Boolean(p)),
      ),
    ]);

    const expected = new Set(campaign.expectedPhases);
    const got = new Set(detectedPhases);

    return {
      campaign,
      found: Boolean(hit),
      detectedPhases,
      missingPhases: campaign.expectedPhases.filter((p) => !got.has(p)),
      unexpectedPhases: detectedPhases.filter((p) => !expected.has(p)),
    };
  });
}
