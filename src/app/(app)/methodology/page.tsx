import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { ContextTile, TopBar } from "@/components/ui/top-bar";

function PipelineStep({
  step,
  title,
  description,
  details,
}: {
  step: number;
  title: string;
  description: string;
  details: string[];
}) {
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-accent font-mono text-[11px] font-bold text-inverse">
          {step}
        </span>
        {step < 4 && (
          <div className="mt-1 h-full w-px bg-line" />
        )}
      </div>
      <div className="pb-6">
        <h3 className="text-[13px] font-semibold text-ink">{title}</h3>
        <p className="mt-1 text-[12px] leading-[19px] text-muted">
          {description}
        </p>
        {details.length > 0 && (
          <ul className="mt-2 flex flex-col gap-1">
            {details.map((d) => (
              <li
                key={d}
                className="flex items-start gap-2 text-[11px] leading-[17px] text-muted"
              >
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent opacity-60" />
                {d}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function FormulaRow({
  label,
  formula,
  weight,
}: {
  label: string;
  formula: string;
  weight: string;
}) {
  return (
    <div className="flex items-start gap-3 border-b border-line px-3 py-2.5 last:border-b-0">
      <span className="w-28 shrink-0 text-[11px] font-semibold text-ink">
        {label}
      </span>
      <code className="flex-1 font-mono text-[11px] text-muted">{formula}</code>
      <span className="shrink-0 text-[10px] text-subtle">{weight}</span>
    </div>
  );
}

function ClassificationRule({
  source,
  phase,
  rule,
}: {
  source: string;
  phase: string;
  rule: string;
}) {
  return (
    <div className="flex items-start gap-2 border-b border-line px-3 py-2 last:border-b-0">
      <span className="w-20 shrink-0 font-mono text-[10px] font-medium text-accent">
        {source}
      </span>
      <span className="w-24 shrink-0 font-mono text-[10px] text-ink">
        {phase}
      </span>
      <span className="text-[11px] text-muted">{rule}</span>
    </div>
  );
}

export default function MethodologyPage() {
  return (
    <>
      <TopBar>
        <ContextTile kicker="system design" title="Methodology" />
      </TopBar>

      <main className="min-h-0 flex-1 overflow-auto p-3">
        <div className="mx-auto flex max-w-[48rem] flex-col gap-2">
          {/* Overview */}
          <Card>
            <CardHeader title="Correlation engine overview" />
            <CardBody className="p-3">
              <p className="text-[12px] leading-[19px] text-muted">
                The GCTU-SIEM correlation engine is the core contribution of
                this project. While the ELK stack (Elasticsearch, Logstash,
                Kibana) and Suricata provide event collection and individual
                alert detection, they process each log line in isolation. The
                correlation engine bridges this gap: it takes events from
                multiple heterogeneous sources, classifies each into a
                kill-chain phase, groups them by attacker-victim IP pairs, and
                detects multi-stage attack campaigns that no single alert could
                reveal.
              </p>
              <p className="mt-3 text-[12px] leading-[19px] text-muted">
                The engine implements the five observable phases of the
                Lockheed Martin Cyber Kill Chain. Weaponization is excluded
                because it occurs offline on the attacker&apos;s machine and is
                unobservable from network or endpoint telemetry. Actions on
                Objectives requires Data Loss Prevention (DLP) integration
                beyond the scope of this engine.
              </p>
            </CardBody>
          </Card>

          {/* Pipeline */}
          <Card>
            <CardHeader title="Processing pipeline" />
            <CardBody className="p-3">
              <PipelineStep
                step={1}
                title="Ingestion"
                description="Raw security logs are parsed from multiple sources into a unified NormalizedEvent format. Each event is tagged with its source, timestamp, IP addresses, ports, and payload metadata."
                details={[
                  "Two intake paths: file upload on Correlate, or a live poll from Elasticsearch using the same parsers",
                  "Suricata EVE JSON — network alerts, HTTP requests, SMB sessions, flow records, anomalies",
                  "Windows Security CSV — Event IDs 4624 (successful logon), 4625 (failed logon), 4798 (group enumeration)",
                  "PowerShell Operational CSV — script block logging, command invocations",
                  "Auto-detect takes the top 3 Suricata alert source IPs as attackers and top destinations as victims; high-volume non-standard ports between that pair are treated as C2",
                  "Endpoint events (Windows / PowerShell) have no IPs; they are merged into the primary detected pair",
                  "Flow filtering reduces noise: only scan probes and attack-relevant port traffic are kept",
                ]}
              />
              <PipelineStep
                step={2}
                title="Classification"
                description="Each normalized event is assigned a kill-chain phase based on source-specific rules. Rules are anchored on documented attack signatures and network behaviour patterns."
                details={[
                  "Rule matching uses signature text, alert categories, event IDs, port numbers, and script content",
                  "Suricata events use both signature-based (alert text) and behavioural (flow state, packet counts) classification",
                  "PowerShell events are classified by matching command names against known exploitation and persistence markers",
                  "Events that don't match any rule are left unclassified and excluded from correlation",
                ]}
              />
              <PipelineStep
                step={3}
                title="Correlation"
                description="Classified events are grouped by (attacker_ip, victim_ip) pairs. Bidirectional traffic (e.g., a reverse shell callback from victim to attacker) is normalised into the same group. Endpoint events (Windows/PowerShell) that lack IP addresses are merged into the primary network group."
                details={[
                  "Groups with events spanning 2 or more distinct kill-chain phases are flagged as multi-stage incidents",
                  "Single-phase groups (e.g., only reconnaissance) are not elevated to incidents — they remain individual alerts",
                  "This IP-pair grouping is the key mechanism: it reconstructs a coordinated attack campaign from hundreds of disconnected alerts",
                ]}
              />
              <PipelineStep
                step={4}
                title="Risk scoring"
                description="Each incident receives a weighted risk score (0–100) based on attack breadth, milestone severity, and velocity. The score determines the severity level displayed to the operator."
                details={[
                  "Breadth: how many of the 5 kill-chain phases the attacker completed",
                  "Milestones: bonus points for exploitation (code execution), persistence (backdoors), and C2 (remote control)",
                  "Velocity: faster attacks score higher because they leave less time for human response",
                ]}
              />
            </CardBody>
          </Card>

          {/* Classification rules */}
          <Card>
            <CardHeader title="Classification rule summary" />
            <CardBody className="p-0">
              <div className="border-b border-line-strong bg-field px-3 py-1.5">
                <div className="flex items-center gap-2">
                  <span className="w-20 font-mono text-[9px] font-semibold uppercase tracking-wider text-subtle">
                    Source
                  </span>
                  <span className="w-24 font-mono text-[9px] font-semibold uppercase tracking-wider text-subtle">
                    Phase
                  </span>
                  <span className="font-mono text-[9px] font-semibold uppercase tracking-wider text-subtle">
                    Rule
                  </span>
                </div>
              </div>
              <ClassificationRule
                source="Suricata"
                phase="Recon"
                rule="Alert signatures containing scan/nmap/portscan, or categories like attempted-recon; SYN-only flow probes (no reply); RST responses; SMB enumeration between known hosts"
              />
              <ClassificationRule
                source="Suricata"
                phase="Delivery"
                rule="HTTP traffic between attacker and victim hosts; any HTTP request fetching .exe, .ps1, or .bat files"
              />
              <ClassificationRule
                source="Suricata"
                phase="C2"
                rule="Traffic on configured C2 ports (default 4444, 5555) between known hosts with >4 packets exchanged (eliminates scan probes); anomaly events between known hosts"
              />
              <ClassificationRule
                source="PowerShell"
                phase="Exploitation"
                rule="Commands matching: Get-Process, Get-LocalUser, Get-NetTCPConnection, Invoke-Expression, DownloadString, Mimikatz, whoami, systeminfo, and 20+ other offensive markers"
              />
              <ClassificationRule
                source="PowerShell"
                phase="Persistence"
                rule="Commands matching: CurrentVersion\Run (registry autorun), schtasks (scheduled tasks), New-Service, Set-ItemProperty on startup paths"
              />
              <ClassificationRule
                source="Win Security"
                phase="Exploitation"
                rule="Event ID 4624 (successful logon — valid-accounts access), Event ID 4798 (user group membership enumeration)"
              />
              <ClassificationRule
                source="Win Security"
                phase="Recon"
                rule="Event ID 4625 (failed logon — brute force indicator)"
              />
            </CardBody>
          </Card>

          {/* Scoring formula */}
          <Card>
            <CardHeader title="Risk scoring formula" />
            <CardBody className="p-0">
              <div className="border-b border-line-strong bg-field px-3 py-2">
                <code className="font-mono text-[11px] text-ink">
                  risk = clamp(breadth + exploitation + persistence + C2 +
                  velocity, 0, 100)
                </code>
              </div>
              <FormulaRow
                label="Breadth"
                formula="phaseCount / 5 × 50"
                weight="0–50 pts"
              />
              <FormulaRow
                label="Exploitation"
                formula="15 if exploitation phase detected"
                weight="+15 pts"
              />
              <FormulaRow
                label="Persistence"
                formula="15 if persistence phase detected"
                weight="+15 pts"
              />
              <FormulaRow
                label="C2"
                formula="15 if command_and_control detected"
                weight="+15 pts"
              />
              <FormulaRow
                label="Velocity"
                formula="10 if ≤1h, 7 if ≤6h, 4 if ≤24h, else 1"
                weight="1–10 pts"
              />
            </CardBody>
          </Card>

          {/* Severity thresholds */}
          <Card>
            <CardHeader title="Severity thresholds" />
            <CardBody className="p-3">
              <div className="flex flex-col gap-2">
                {([
                  ["Critical", "≥ 80", "#ef4444", "Full multi-stage compromise with code execution, persistence, and remote control. Requires immediate incident response."],
                  ["High", "60–79", "#c55f5f", "Active exploitation detected with significant kill-chain progression. Prompt investigation recommended."],
                  ["Medium", "40–59", "#a88940", "Partial attack sequence detected. Could be automated probing or an attack in early stages."],
                  ["Low", "0–39", "#6fbf73", "Limited activity, typically only scanning or failed login attempts. Monitor for escalation."],
                ] as const).map(([level, range, color, desc]) => (
                  <div
                    key={level}
                    className="flex items-start gap-3 rounded-md border border-line px-3 py-2"
                  >
                    <div className="flex w-20 shrink-0 items-center gap-1.5">
                      <span
                        className="h-2 w-2 rounded-full"
                        style={{ background: color }}
                      />
                      <span className="font-mono text-[11px] font-semibold" style={{ color }}>
                        {level}
                      </span>
                    </div>
                    <span className="w-12 shrink-0 font-mono text-[10px] text-subtle">
                      {range}
                    </span>
                    <span className="text-[11px] leading-[17px] text-muted">
                      {desc}
                    </span>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>

          {/* Design decisions */}
          <Card>
            <CardHeader title="Key design decisions" />
            <CardBody className="p-3">
              <div className="flex flex-col gap-3">
                {[
                  {
                    q: "Why auto-detect attacker and victim IPs?",
                    a: "A lab or SME operator should not have to name hosts before a run. The engine ranks Suricata alert sources and destinations and keeps the top three of each. Endpoint events are then attached to the primary pair. This is a heuristic, not ground truth — Evaluation therefore does not treat every cartesian pairing of those IPs as a missed campaign.",
                  },
                  {
                    q: "Why IP-pair grouping instead of time-window clustering?",
                    a: "Time-window clustering groups events that occur close together, but concurrent attacks against different targets would be merged into one incident. IP-pair grouping ensures each attacker→victim relationship is tracked independently, even if attacks overlap in time.",
                  },
                  {
                    q: "Why require ≥2 phases for an incident?",
                    a: "A single-phase group (e.g., only reconnaissance) is a routine alert, not a confirmed attack. Requiring multiple phases filters out background noise (port scans, failed logins) and surfaces only coordinated campaigns where the attacker progressed through the kill chain.",
                  },
                  {
                    q: "Why merge endpoint events into network groups?",
                    a: "Windows Security and PowerShell logs don't contain network IPs — they record what happened on the target machine. Since these events ran on the victim host during the same attack campaign, merging them into the attacker→victim network group reconstructs the complete picture across both network and endpoint telemetry.",
                  },
                  {
                    q: "Why separate velocity from breadth in scoring?",
                    a: "An attack that completes 3 phases in 30 minutes is more dangerous than one that takes 3 days — the defender has less time to detect and respond. Velocity rewards the detection of fast-moving attacks, which are often automated and harder to stop manually.",
                  },
                  {
                    q: "Why 5 phases instead of the full 7-phase kill chain?",
                    a: "The Lockheed Martin model includes Weaponization (building the payload) and Actions on Objectives (data exfiltration). Weaponization occurs offline on the attacker's machine and produces no network or endpoint telemetry. Actions on Objectives requires DLP sensors that are outside the scope of this lightweight SIEM. The 5 implemented phases represent the detectable subset observable from IDS and endpoint logs.",
                  },
                ].map((item) => (
                  <div key={item.q}>
                    <p className="text-[12px] font-semibold text-ink">
                      {item.q}
                    </p>
                    <p className="mt-1 text-[11px] leading-[17px] text-muted">
                      {item.a}
                    </p>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Evaluation method" />
            <CardBody className="p-3">
              <p className="text-[12px] leading-[19px] text-muted">
                Evaluation measures this correlation engine, not Elasticsearch
                or Suricata. The headline metric is alert reduction: classified
                events divided by incidents. A campaign is counted only when
                stored events between a pair already span two or more
                kill-chain phases — the same rule the engine uses to create an
                incident. Crossing every auto-detected IP would invent
                campaigns that never existed in the logs.
              </p>
              <ul className="mt-3 flex flex-col gap-1">
                {[
                  "Reconstructed — a multi-stage pair that became an incident (true positive)",
                  "Missed — a multi-stage pair that did not become an incident (false negative)",
                  "Extra / false positive — an incident the operator rejects on review",
                  "Suppressed — single-phase pairs, excluded by design and not scored as misses",
                  "Precision = TP / (TP + FP), Recall = TP / (TP + FN), F1 = harmonic mean of both",
                ].map((d) => (
                  <li
                    key={d}
                    className="flex items-start gap-2 text-[11px] leading-[17px] text-muted"
                  >
                    <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent opacity-60" />
                    {d}
                  </li>
                ))}
              </ul>
            </CardBody>
          </Card>

          {/* Architecture */}
          <Card>
            <CardHeader title="Technology stack" />
            <CardBody className="p-3">
              <div className="grid grid-cols-2 gap-x-6 gap-y-2">
                {[
                  ["Correlation engine", "TypeScript (Node.js)"],
                  ["Web framework", "Next.js 16 (App Router)"],
                  ["Database", "Supabase (PostgreSQL)"],
                  ["IDS source", "Suricata via Elasticsearch / EVE JSON"],
                  ["Endpoint sources", "Windows Event Viewer CSV exports"],
                  ["Authentication", "Supabase Auth (email/password + RLS)"],
                  ["Visualisation", "Recharts, Tailwind CSS"],
                  ["Alert email", "Resend (critical / warning + manual forward)"],
                  ["Testing", "Vitest (34 unit tests)"],
                ].map(([label, value]) => (
                  <div key={label} className="flex flex-col gap-0.5 py-1">
                    <span className="text-[10px] font-medium uppercase tracking-wider text-subtle">
                      {label}
                    </span>
                    <span className="text-[12px] text-ink">{value}</span>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>
        </div>
      </main>
    </>
  );
}
