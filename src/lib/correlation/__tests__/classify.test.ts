import { describe, it, expect, beforeEach } from 'vitest';
import { classifyPhase, classifyAll } from '../classify';
import { resetConfigCache } from '../config';
import type { NormalizedEvent } from '../types';

beforeEach(() => {
  process.env.KNOWN_ATTACKER_IPS = '192.168.64.2';
  process.env.KNOWN_VICTIM_IPS = '192.168.64.3';
  process.env.KNOWN_C2_PORTS = '4444,5555';
  resetConfigCache();
});

function suricataEvent(overrides: Partial<NormalizedEvent> & { raw?: unknown }): NormalizedEvent {
  return {
    source: 'suricata',
    eventTime: '2025-01-15T10:00:00Z',
    raw: {},
    ...overrides,
  };
}

describe('classifyPhase — Suricata events', () => {
  it('classifies nmap scan alert as reconnaissance', () => {
    const ev = suricataEvent({
      eventType: 'alert',
      srcIp: '192.168.64.2',
      destIp: '192.168.64.3',
      signature: 'ET SCAN Nmap SYN Scan',
      category: 'attempted-recon',
    });
    expect(classifyPhase(ev)).toBe('reconnaissance');
  });

  it('classifies SYN-only flow probe as reconnaissance', () => {
    const ev = suricataEvent({
      eventType: 'flow',
      srcIp: '192.168.64.2',
      destIp: '192.168.64.3',
      destPort: 80,
      raw: {
        tcp: { state: 'syn_sent' },
        flow: { pkts_toserver: 1, pkts_toclient: 0 },
      },
    });
    expect(classifyPhase(ev)).toBe('reconnaissance');
  });

  it('classifies HTTP between hosts as delivery', () => {
    const ev = suricataEvent({
      eventType: 'http',
      srcIp: '192.168.64.2',
      destIp: '192.168.64.3',
      raw: { http: { url: '/payload' } },
    });
    expect(classifyPhase(ev)).toBe('delivery');
  });

  it('classifies .exe download from any host as delivery', () => {
    const ev = suricataEvent({
      eventType: 'http',
      srcIp: '10.0.0.1',
      destIp: '10.0.0.2',
      raw: { http: { url: '/malware.exe' } },
    });
    expect(classifyPhase(ev)).toBe('delivery');
  });

  it('classifies C2 port traffic with data as command_and_control', () => {
    const ev = suricataEvent({
      eventType: 'flow',
      srcIp: '192.168.64.3',
      destIp: '192.168.64.2',
      destPort: 4444,
      raw: {
        flow: { pkts_toserver: 10, pkts_toclient: 8 },
      },
    });
    expect(classifyPhase(ev)).toBe('command_and_control');
  });

  it('classifies C2 port SYN-only probe as reconnaissance (not C2)', () => {
    const ev = suricataEvent({
      eventType: 'flow',
      srcIp: '192.168.64.2',
      destIp: '192.168.64.3',
      destPort: 4444,
      raw: {
        flow: { pkts_toserver: 1, pkts_toclient: 0 },
      },
    });
    expect(classifyPhase(ev)).toBe('reconnaissance');
  });

  it('classifies SMB between hosts as reconnaissance', () => {
    const ev = suricataEvent({
      eventType: 'smb',
      srcIp: '192.168.64.2',
      destIp: '192.168.64.3',
    });
    expect(classifyPhase(ev)).toBe('reconnaissance');
  });

  it('returns undefined for unrelated traffic', () => {
    const ev = suricataEvent({
      eventType: 'dns',
      srcIp: '10.0.0.5',
      destIp: '8.8.8.8',
    });
    expect(classifyPhase(ev)).toBeUndefined();
  });
});

describe('classifyPhase — PowerShell events', () => {
  it('classifies Get-Process as exploitation', () => {
    const ev: NormalizedEvent = {
      source: 'powershell',
      eventTime: '2025-01-15T10:30:00Z',
      message: 'CommandInvocation(Get-Process): "Get-Process"',
      raw: {},
    };
    expect(classifyPhase(ev)).toBe('exploitation');
  });

  it('classifies registry persistence as persistence', () => {
    const ev: NormalizedEvent = {
      source: 'powershell',
      eventTime: '2025-01-15T11:00:00Z',
      message: 'Set-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name WindowsUpdate',
      raw: {},
    };
    expect(classifyPhase(ev)).toBe('persistence');
  });

  it('classifies schtasks as persistence', () => {
    const ev: NormalizedEvent = {
      source: 'powershell',
      eventTime: '2025-01-15T11:00:00Z',
      message: 'schtasks /create /sc minute /tn "Updater"',
      raw: {},
    };
    expect(classifyPhase(ev)).toBe('persistence');
  });

  it('returns undefined for benign PowerShell', () => {
    const ev: NormalizedEvent = {
      source: 'powershell',
      eventTime: '2025-01-15T10:30:00Z',
      message: 'Write-Host "Hello World"',
      raw: {},
    };
    expect(classifyPhase(ev)).toBeUndefined();
  });
});

describe('classifyPhase — Windows Security events', () => {
  it('classifies event 4624 (successful logon) as exploitation', () => {
    const ev: NormalizedEvent = {
      source: 'windows_security',
      eventTime: '2025-01-15T10:15:00Z',
      eventId: 4624,
      raw: {},
    };
    expect(classifyPhase(ev)).toBe('exploitation');
  });

  it('classifies event 4625 (failed logon) as reconnaissance', () => {
    const ev: NormalizedEvent = {
      source: 'windows_security',
      eventTime: '2025-01-15T10:10:00Z',
      eventId: 4625,
      raw: {},
    };
    expect(classifyPhase(ev)).toBe('reconnaissance');
  });

  it('classifies event 4798 (group enumeration) as exploitation', () => {
    const ev: NormalizedEvent = {
      source: 'windows_security',
      eventTime: '2025-01-15T10:20:00Z',
      eventId: 4798,
      raw: {},
    };
    expect(classifyPhase(ev)).toBe('exploitation');
  });

  it('returns undefined for unrelated event IDs', () => {
    const ev: NormalizedEvent = {
      source: 'windows_security',
      eventTime: '2025-01-15T10:00:00Z',
      eventId: 4688,
      raw: {},
    };
    expect(classifyPhase(ev)).toBeUndefined();
  });
});

describe('classifyAll', () => {
  it('tags all classifiable events and returns the array', () => {
    const events: NormalizedEvent[] = [
      suricataEvent({
        eventType: 'alert',
        srcIp: '192.168.64.2',
        destIp: '192.168.64.3',
        signature: 'ET SCAN Nmap',
      }),
      {
        source: 'powershell',
        eventTime: '2025-01-15T10:30:00Z',
        message: 'Get-Process',
        raw: {},
      },
      suricataEvent({
        eventType: 'dns',
        srcIp: '10.0.0.5',
        destIp: '8.8.8.8',
      }),
    ];

    const result = classifyAll(events);
    expect(result).toBe(events);
    expect(events[0].killChainPhase).toBe('reconnaissance');
    expect(events[1].killChainPhase).toBe('exploitation');
    expect(events[2].killChainPhase).toBeUndefined();
  });
});

describe('configurable IPs', () => {
  it('uses custom attacker/victim IPs from config', () => {
    process.env.KNOWN_ATTACKER_IPS = '10.0.0.100';
    process.env.KNOWN_VICTIM_IPS = '10.0.0.200';
    resetConfigCache();

    const ev = suricataEvent({
      eventType: 'http',
      srcIp: '10.0.0.100',
      destIp: '10.0.0.200',
      raw: { http: { url: '/payload' } },
    });
    expect(classifyPhase(ev)).toBe('delivery');

    // Original experiment IPs should NOT match
    const evOld = suricataEvent({
      eventType: 'http',
      srcIp: '192.168.64.2',
      destIp: '192.168.64.3',
      raw: { http: { url: '/payload' } },
    });
    expect(classifyPhase(evOld)).toBeUndefined();
  });
});
