import { describe, it, expect } from 'vitest';
import {
  parseGroundTruth,
  compareToGroundTruth,
  GroundTruthError,
  samePair,
  type GroundTruth,
} from '../ground-truth';

const VALID = {
  label: 'Lab',
  campaigns: [
    {
      attackerIp: '192.168.64.2',
      victimIp: '192.168.64.3',
      expectedPhases: ['reconnaissance', 'delivery', 'exploitation'],
      note: 'staged',
    },
  ],
};

describe('parseGroundTruth — validation', () => {
  it('accepts a well-formed document', () => {
    const gt = parseGroundTruth(VALID);
    expect(gt.label).toBe('Lab');
    expect(gt.campaigns).toHaveLength(1);
    expect(gt.campaigns[0].note).toBe('staged');
  });

  it('canonicalises phase synonyms', () => {
    const gt = parseGroundTruth({
      campaigns: [
        {
          attackerIp: '10.0.0.1',
          victimIp: '10.0.0.2',
          expectedPhases: ['Recon', 'installation', 'C2', 'command-and-control'],
        },
      ],
    });
    // installation → persistence, C2/command-and-control → command_and_control (deduped)
    expect(gt.campaigns[0].expectedPhases).toEqual([
      'reconnaissance',
      'persistence',
      'command_and_control',
    ]);
  });

  it('sorts expected phases into kill-chain order', () => {
    const gt = parseGroundTruth({
      campaigns: [
        {
          attackerIp: '10.0.0.1',
          victimIp: '10.0.0.2',
          expectedPhases: ['command_and_control', 'reconnaissance', 'exploitation'],
        },
      ],
    });
    expect(gt.campaigns[0].expectedPhases).toEqual([
      'reconnaissance',
      'exploitation',
      'command_and_control',
    ]);
  });

  it.each([
    ['a non-object', 42],
    ['a missing campaigns array', { label: 'x' }],
    ['an empty campaigns array', { campaigns: [] }],
    [
      'a missing attackerIp',
      { campaigns: [{ victimIp: '10.0.0.2', expectedPhases: ['recon'] }] },
    ],
    [
      'a non-IP attackerIp',
      {
        campaigns: [
          { attackerIp: 'not an ip', victimIp: '10.0.0.2', expectedPhases: ['recon'] },
        ],
      },
    ],
    [
      'identical attacker and victim',
      {
        campaigns: [
          { attackerIp: '10.0.0.1', victimIp: '10.0.0.1', expectedPhases: ['recon'] },
        ],
      },
    ],
    [
      'empty expectedPhases',
      { campaigns: [{ attackerIp: '10.0.0.1', victimIp: '10.0.0.2', expectedPhases: [] }] },
    ],
  ])('rejects %s', (_label, input) => {
    expect(() => parseGroundTruth(input)).toThrow(GroundTruthError);
  });

  it('rejects the same pair declared twice, in either direction', () => {
    expect(() =>
      parseGroundTruth({
        campaigns: [
          { attackerIp: '10.0.0.1', victimIp: '10.0.0.2', expectedPhases: ['recon'] },
          { attackerIp: '10.0.0.2', victimIp: '10.0.0.1', expectedPhases: ['delivery'] },
        ],
      }),
    ).toThrow(/duplicates/);
  });
});

describe('samePair', () => {
  it('matches in both directions', () => {
    expect(samePair('a', 'b', 'a', 'b')).toBe(true);
    expect(samePair('a', 'b', 'b', 'a')).toBe(true);
    expect(samePair('a', 'b', 'a', 'c')).toBe(false);
  });
});

describe('compareToGroundTruth — the failure modes derived ground truth cannot see', () => {
  const truth: GroundTruth = parseGroundTruth({
    campaigns: [
      {
        attackerIp: '192.168.64.2',
        victimIp: '192.168.64.3',
        expectedPhases: ['reconnaissance', 'delivery', 'exploitation', 'persistence'],
      },
      {
        attackerIp: '10.0.0.5',
        victimIp: '10.0.0.9',
        expectedPhases: ['reconnaissance', 'command_and_control'],
      },
    ],
  });

  it('counts a wholly undetected campaign as a false negative', () => {
    // The second campaign produced NO incident at all. Under the derived
    // method it would never appear in the answer key and recall would read
    // 100%; here it is correctly a miss.
    const result = compareToGroundTruth(truth, [
      {
        attackerIp: '192.168.64.2',
        victimIp: '192.168.64.3',
        phases: ['reconnaissance', 'delivery', 'exploitation', 'persistence'],
      },
    ]);

    expect(result[0].found).toBe(true);
    expect(result[1].found).toBe(false);
    expect(result[1].detectedPhases).toEqual([]);
    expect(result[1].missingPhases).toEqual(['reconnaissance', 'command_and_control']);

    const recall = result.filter((r) => r.found).length / result.length;
    expect(recall).toBe(0.5);
  });

  it('reports partial reconstruction when phases are missing', () => {
    const result = compareToGroundTruth(truth, [
      {
        attackerIp: '192.168.64.2',
        victimIp: '192.168.64.3',
        phases: ['reconnaissance', 'delivery'],
      },
      { attackerIp: '10.0.0.5', victimIp: '10.0.0.9', phases: ['reconnaissance', 'c2'] },
    ]);

    expect(result[0].found).toBe(true);
    expect(result[0].missingPhases).toEqual(['exploitation', 'persistence']);
    expect(result[0].unexpectedPhases).toEqual([]);
  });

  it('reports over-classification as unexpected phases', () => {
    const result = compareToGroundTruth(truth, [
      {
        attackerIp: '192.168.64.2',
        victimIp: '192.168.64.3',
        phases: [
          'reconnaissance',
          'delivery',
          'exploitation',
          'persistence',
          'command_and_control',
        ],
      },
    ]);

    expect(result[0].found).toBe(true);
    expect(result[0].missingPhases).toEqual([]);
    expect(result[0].unexpectedPhases).toEqual(['command_and_control']);
  });

  it('matches a campaign detected in the reverse direction', () => {
    const result = compareToGroundTruth(truth, [
      {
        attackerIp: '192.168.64.3',
        victimIp: '192.168.64.2',
        phases: ['reconnaissance', 'delivery', 'exploitation', 'persistence'],
      },
    ]);
    expect(result[0].found).toBe(true);
    expect(result[0].missingPhases).toEqual([]);
  });

  it('normalises detected phase synonyms before comparing', () => {
    const result = compareToGroundTruth(truth, [
      { attackerIp: '10.0.0.5', victimIp: '10.0.0.9', phases: ['Recon', 'cnc'] },
    ]);
    expect(result[1].missingPhases).toEqual([]);
    expect(result[1].unexpectedPhases).toEqual([]);
  });
});
