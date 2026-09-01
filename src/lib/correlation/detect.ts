export type LogType = 'suricata' | 'windows_security' | 'powershell' | 'unknown';

export function detectLogTypeFromText(text: string, fileName: string): LogType {
  const firstLine = text.split('\n').find((l) => l.trim()) ?? '';

  // JSON: Suricata EVE format — either JSON lines or a JSON array
  if (fileName.endsWith('.json') || firstLine.trim().startsWith('{') || firstLine.trim().startsWith('[')) {
    // Try JSON lines first (single object per line)
    if (firstLine.trim().startsWith('{')) {
      try {
        const obj = JSON.parse(firstLine.trim().replace(/,\s*$/, ''));
        if (obj.event_type && obj.timestamp) return 'suricata';
      } catch {}
    }

    // Try JSON array (pretty-printed or compact)
    if (firstLine.trim().startsWith('[')) {
      // Look for key fields anywhere in the text chunk
      if (text.includes('"event_type"') && text.includes('"timestamp"')) {
        return 'suricata';
      }
    }
  }

  // CSV: look at the header row
  const headerLower = firstLine.toLowerCase();
  if (headerLower.includes('date and time') && headerLower.includes('event id')) {
    // Both Windows Security and PowerShell use the same header structure.
    // Distinguish by the Source column value in data rows.
    const dataLines = text.split('\n').slice(1, 6);
    for (const line of dataLines) {
      const lower = line.toLowerCase();
      if (lower.includes('powershell')) return 'powershell';
      if (lower.includes('microsoft-windows-security')) return 'windows_security';
      if (lower.includes('security')) return 'windows_security';
    }
    // Default: if we can't tell, check filename hints
    if (fileName.toLowerCase().includes('powershell') || fileName.toLowerCase().includes('ps')) {
      return 'powershell';
    }
    return 'windows_security';
  }

  return 'unknown';
}

export const LOG_TYPE_LABELS: Record<LogType, string> = {
  suricata: 'Suricata EVE',
  windows_security: 'Windows Security',
  powershell: 'PowerShell',
  unknown: 'Unknown',
};
