import { describe, it, expect, beforeEach } from 'vitest';
import { correlate } from '../correlate';
import { resetConfigCache } from '../config';
import type { NormalizedEvent } from '../types';

beforeEach(() => {
  process.env.KNOWN_ATTACKER_IPS = '192.168.64.2';
  process.env.KNOWN_VICTIM_IPS = '192.168.64.3';
  process.env.KNOWN_C2_PORTS = '4444,5555';
  resetConfigCache();
});

function makeEvent(overrides: Partial<NormalizedEvent>): NormalizedEvent {
  return {
    source: 'suricata',
    eventTime: '2025-01-15T10:00:00Z',
    raw: {},
    ...overrides,
  };
}

describe('correlate', () => {
  it('detects a multi-stage incident from events spanning 2+ phases', () => {
    const events: NormalizedEvent[] = [
      makeEvent({
        eventTime: '2025-01-15T10:00:00Z',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'reconnaissance',
      }),
      makeEvent({
        eventTime: '2025-01-15T10:05:00Z',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'delivery',
      }),
      makeEvent({
        source: 'powershell',
        eventTime: '2025-01-15T10:10:00Z',
        killChainPhase: 'exploitation',
      }),
    ];

    const incidents = correlate(events);

    expect(incidents).toHaveLength(1);
    expect(incidents[0].attackerIp).toBe('192.168.64.2');
    expect(incidents[0].victimIp).toBe('192.168.64.3');
    expect(incidents[0].phasesDetected).toContain('reconnaissance');
    expect(incidents[0].phasesDetected).toContain('delivery');
    expect(incidents[0].phasesDetected).toContain('exploitation');
    expect(incidents[0].phaseCount).toBe(3);
    expect(incidents[0].eventCount).toBe(3);
    expect(incidents[0].riskScore).toBeGreaterThan(0);
    expect(incidents[0].severity).toBeDefined();
  });

  it('does NOT produce an incident from single-phase events', () => {
    const events: NormalizedEvent[] = [
      makeEvent({
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'reconnaissance',
      }),
      makeEvent({
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'reconnaissance',
      }),
    ];

    const incidents = correlate(events);
    expect(incidents).toHaveLength(0);
  });

  it('ignores events without a kill-chain phase', () => {
    const events: NormalizedEvent[] = [
      makeEvent({ srcIp: '192.168.64.2', destIp: '192.168.64.3' }),
      makeEvent({ srcIp: '192.168.64.2', destIp: '192.168.64.3' }),
    ];

    const incidents = correlate(events);
    expect(incidents).toHaveLength(0);
  });

  it('returns an empty array for no events', () => {
    expect(correlate([])).toHaveLength(0);
  });

  it('normalises bidirectional traffic into one incident', () => {
    const events: NormalizedEvent[] = [
      makeEvent({
        eventTime: '2025-01-15T10:00:00Z',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'reconnaissance',
      }),
      // Reverse direction (victim → attacker, e.g. reverse shell callback)
      makeEvent({
        eventTime: '2025-01-15T10:30:00Z',
        srcIp: '192.168.64.3',
        destIp: '192.168.64.2',
        killChainPhase: 'command_and_control',
      }),
    ];

    const incidents = correlate(events);
    expect(incidents).toHaveLength(1);
    expect(incidents[0].attackerIp).toBe('192.168.64.2');
    expect(incidents[0].victimIp).toBe('192.168.64.3');
  });

  it('merges endpoint events (no IPs) into the primary group', () => {
    const events: NormalizedEvent[] = [
      makeEvent({
        eventTime: '2025-01-15T10:00:00Z',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'reconnaissance',
      }),
      // PowerShell event — no srcIp/destIp
      makeEvent({
        source: 'powershell',
        eventTime: '2025-01-15T10:20:00Z',
        killChainPhase: 'exploitation',
      }),
    ];

    const incidents = correlate(events);
    expect(incidents).toHaveLength(1);
    expect(incidents[0].eventCount).toBe(2);
    expect(incidents[0].phasesDetected).toContain('exploitation');
  });

  it('sorts incidents by risk score descending', () => {
    const events: NormalizedEvent[] = [
      // Low-risk pair (2 phases)
      makeEvent({
        eventTime: '2025-01-15T10:00:00Z',
        srcIp: '10.0.0.1',
        destIp: '10.0.0.2',
        killChainPhase: 'reconnaissance',
      }),
      makeEvent({
        eventTime: '2025-01-15T10:01:00Z',
        srcIp: '10.0.0.1',
        destIp: '10.0.0.2',
        killChainPhase: 'delivery',
      }),
      // High-risk — main attacker/victim pair (4 phases)
      makeEvent({
        eventTime: '2025-01-15T10:00:00Z',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'reconnaissance',
      }),
      makeEvent({
        eventTime: '2025-01-15T10:05:00Z',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'delivery',
      }),
      makeEvent({
        eventTime: '2025-01-15T10:10:00Z',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'exploitation',
      }),
      makeEvent({
        source: 'powershell',
        eventTime: '2025-01-15T10:15:00Z',
        killChainPhase: 'persistence',
      }),
    ];

    const incidents = correlate(events);
    expect(incidents.length).toBeGreaterThanOrEqual(2);
    expect(incidents[0].riskScore).toBeGreaterThanOrEqual(incidents[1].riskScore);
  });

  it('generates a human-readable summary', () => {
    const events: NormalizedEvent[] = [
      makeEvent({
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'reconnaissance',
        eventTime: '2025-01-15T10:00:00Z',
      }),
      makeEvent({
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'command_and_control',
        eventTime: '2025-01-15T10:30:00Z',
      }),
    ];

    const incidents = correlate(events);
    expect(incidents[0].summary).toContain('192.168.64.2');
    expect(incidents[0].summary).toContain('192.168.64.3');
    expect(incidents[0].summary.length).toBeGreaterThan(10);
  });

  it('records correct firstSeen and lastSeen timestamps', () => {
    const events: NormalizedEvent[] = [
      makeEvent({
        eventTime: '2025-01-15T08:00:00Z',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'reconnaissance',
      }),
      makeEvent({
        eventTime: '2025-01-15T14:00:00Z',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        killChainPhase: 'exploitation',
      }),
    ];

    const incidents = correlate(events);
    expect(incidents[0].firstSeen).toBe('2025-01-15T08:00:00Z');
    expect(incidents[0].lastSeen).toBe('2025-01-15T14:00:00Z');
  });
});
