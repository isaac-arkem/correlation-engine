import { describe, it, expect } from 'vitest';
import { scoreRisk } from '../score';
import type { NormalizedEvent } from '../types';

function makeEvents(count: number, spanHours: number): NormalizedEvent[] {
  const start = new Date('2025-01-15T10:00:00Z').getTime();
  return Array.from({ length: count }, (_, i) => ({
    source: 'suricata' as const,
    eventTime: new Date(start + (i / Math.max(count - 1, 1)) * spanHours * 3600_000).toISOString(),
    raw: {},
  }));
}

describe('scoreRisk', () => {
  it('scores a full 5-phase fast attack as critical', () => {
    const phases = ['reconnaissance', 'delivery', 'exploitation', 'persistence', 'command_and_control'];
    const events = makeEvents(20, 0.5);
    const { riskScore, severity } = scoreRisk(phases, events);

    // breadth: 5/5*50=50, exploitation=15, persistence=15, C2=15, velocity(<=1h)=10 → 100 (clamped)
    expect(riskScore).toBe(100);
    expect(severity).toBe('critical');
  });

  it('scores 2 benign phases as low-medium', () => {
    const phases = ['reconnaissance', 'delivery'];
    const events = makeEvents(5, 48);
    const { riskScore, severity } = scoreRisk(phases, events);

    // breadth: 2/5*50=20, no exploitation/persistence/C2, velocity(48h)=1 → 21
    expect(riskScore).toBe(21);
    expect(severity).toBe('low');
  });

  it('boosts score when exploitation is present', () => {
    const withExploit = scoreRisk(['reconnaissance', 'exploitation'], makeEvents(5, 2));
    const withoutExploit = scoreRisk(['reconnaissance', 'delivery'], makeEvents(5, 2));

    expect(withExploit.riskScore).toBeGreaterThan(withoutExploit.riskScore);
  });

  it('boosts score for faster attacks (velocity)', () => {
    const phases = ['reconnaissance', 'delivery', 'exploitation'];
    const fast = scoreRisk(phases, makeEvents(10, 0.5));
    const slow = scoreRisk(phases, makeEvents(10, 48));

    expect(fast.riskScore).toBeGreaterThan(slow.riskScore);
  });

  it('clamps score to 0-100 range', () => {
    const phases = ['reconnaissance', 'delivery', 'exploitation', 'persistence', 'command_and_control'];
    const events = makeEvents(100, 0.1);
    const { riskScore } = scoreRisk(phases, events);

    expect(riskScore).toBeGreaterThanOrEqual(0);
    expect(riskScore).toBeLessThanOrEqual(100);
  });

  it('handles a single event without crashing', () => {
    const { riskScore, severity } = scoreRisk(['reconnaissance', 'exploitation'], makeEvents(1, 0));
    expect(riskScore).toBeGreaterThan(0);
    expect(['low', 'medium', 'high', 'critical']).toContain(severity);
  });

  it('assigns correct severity thresholds', () => {
    // Low: < 40
    const low = scoreRisk(['reconnaissance', 'delivery'], makeEvents(3, 100));
    expect(low.severity).toBe('low');

    // Medium: 40-59
    const med = scoreRisk(['reconnaissance', 'delivery', 'exploitation'], makeEvents(10, 10));
    expect(med.severity).toBe('medium');

    // Critical: >= 80
    const crit = scoreRisk(
      ['reconnaissance', 'delivery', 'exploitation', 'persistence', 'command_and_control'],
      makeEvents(50, 0.5),
    );
    expect(crit.severity).toBe('critical');
  });
});
