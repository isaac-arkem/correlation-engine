import type { EventSource, NormalizedEvent } from '../types';
import { parseSuricataEve, parseWindowsSecurity, parsePowerShell } from '../parse';

export class FileSource implements EventSource {
  constructor(
    private paths: {
      evePath: string;
      winSecurityPath: string;
      psOperationalPath: string;
    }
  ) {}

  async getSecurityEvents(
    range?: { from?: string; to?: string }
  ): Promise<NormalizedEvent[]> {
    const [suricata, winSecurity, powershell] = await Promise.all([
      parseSuricataEve(this.paths.evePath, range),
      parseWindowsSecurity(this.paths.winSecurityPath, range),
      parsePowerShell(this.paths.psOperationalPath, range),
    ]);

    const all = [...suricata, ...winSecurity, ...powershell];
    all.sort((a, b) => a.eventTime.localeCompare(b.eventTime));

    console.log(
      `[FileSource] Total: ${all.length} events (suricata: ${suricata.length}, windows_security: ${winSecurity.length}, powershell: ${powershell.length})`
    );

    return all;
  }
}
