/**
 * Canonical kill-chain phase vocabulary.
 *
 * Shared by the persistence layer and the ground-truth loader so that a
 * declared campaign and a stored incident can never disagree about what
 * "installation" or "c2" means.
 */

export const CANONICAL_PHASES: Record<string, string> = {
  reconnaissance: 'reconnaissance',
  recon: 'reconnaissance',
  scanning: 'reconnaissance',
  discovery: 'reconnaissance',
  delivery: 'delivery',
  weaponization: 'delivery',
  exploitation: 'exploitation',
  exploit: 'exploitation',
  execution: 'exploitation',
  persistence: 'persistence',
  installation: 'persistence',
  command_and_control: 'command_and_control',
  'command-and-control': 'command_and_control',
  c2: 'command_and_control',
  cnc: 'command_and_control',
};

/** The five phases the engine can observe, in kill-chain order. */
export const PHASE_ORDER = [
  'reconnaissance',
  'delivery',
  'exploitation',
  'persistence',
  'command_and_control',
] as const;

export function normalizePhase(phase: string | undefined | null): string | null {
  if (!phase) return null;
  const key = phase.toLowerCase().trim().replace(/[\s-]+/g, '_');
  return CANONICAL_PHASES[key] ?? key;
}

export function sortPhases(phases: string[]): string[] {
  return [...phases].sort(
    (a, b) =>
      (PHASE_ORDER.indexOf(a as never) + 1 || 99) -
      (PHASE_ORDER.indexOf(b as never) + 1 || 99),
  );
}
