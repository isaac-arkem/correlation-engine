import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { ContextTile, TopBar } from "@/components/ui/top-bar";

const SECTIONS = [
  {
    title: "What is GCTU-SIEM?",
    content:
      "GCTU-SIEM is a lightweight correlation engine for small and medium enterprises. ELK and Suricata already collect and detect individual events. This app classifies those events into kill-chain phases, groups them by attacker→victim, and presents multi-stage incidents so you can see a campaign instead of hundreds of disconnected alerts.",
  },
  {
    title: "How does it work?",
    content:
      "Four engine steps, then the dashboard: (1) Ingestion — upload log files on Correlate, or pull live events from Elasticsearch. (2) Classification — each event is tagged with a kill-chain phase, or dropped if it matches no rule. (3) Correlation — events are grouped by attacker→victim IP pair; only groups with two or more phases become incidents. (4) Scoring — each incident gets a 0–100 risk score. Insights then lists those incidents. Evaluation measures how much alert volume was reduced. Critical and warning alerts can be forwarded by email.",
  },
  {
    title: "What is the kill chain?",
    content:
      "The Cyber Kill Chain is a model that breaks a cyber attack into stages. This engine uses the five phases visible in network and endpoint logs. Reconnaissance: the attacker scans for weaknesses. Delivery: a payload is sent to the target. Exploitation: access or code execution is achieved. Persistence: a backdoor or autorun is installed. Command & Control (C2): the compromised host talks back to the attacker. Weaponization and Actions on Objectives are omitted because they are not observable from these logs.",
  },
  {
    title: "What does the risk score mean?",
    content:
      "The score is 0–100. It rises with how many of the five phases were completed, plus bonuses for exploitation, persistence, C2, and how quickly the attack moved. Thresholds: 0–39 Low, 40–59 Medium, 60–79 High, 80–100 Critical. A Critical score usually means a full multi-stage compromise and needs immediate attention.",
  },
  {
    title: "What are the data sources?",
    content:
      "Supported inputs are Suricata EVE JSON (network alerts, HTTP, SMB, flows), Windows Security CSV (Event IDs such as 4624, 4625, 4798), and PowerShell Operational CSV (script and command logging). You can upload files on Correlate, or connect Elasticsearch and poll the same event types live. The engine auto-detects the top attacker and victim IPs from Suricata alerts so you do not have to name them first.",
  },
  {
    title: "How do I run a correlation?",
    content:
      "Open Correlate. For a file run, upload one or more supported logs, give the run a label, and start it. For a live run, choose an Elasticsearch connection and a time window; the engine pulls new events on a poll and appends them to that dataset. Each run is stored separately. Switch datasets from the run selector on Insights or Evaluation.",
  },
  {
    title: "What is Insights?",
    content:
      "Insights is the operator home page. Pick a correlation run and an optional date range to list incidents, overview counts, and a live-session banner if that run is still polling. Open an incident for the kill-chain timeline, events, recommended actions, status, and a PDF export. The date range is kept when you move between Insights and an incident.",
  },
  {
    title: "What should I do when an incident is detected?",
    content:
      "Open the incident from Insights or from the email link. (1) Read the 'What happened' summary. (2) Check the risk score — Critical and High need prompt attention. (3) Follow Recommended actions. (4) Set status to Investigating. (5) Export a PDF if you need a record. (6) Mark Resolved when the issue is handled. Use the bell to forward the alert to an engineer.",
  },
  {
    title: "How do notifications work?",
    content:
      "The bell (top-right on desktop, header on mobile) lists in-app alerts. A completed run, new critical or high incidents, and live-poll activity create notifications. Critical and warning items can be emailed automatically. Forward to engineer sends the same alert with a button back to the incident or Insights page. Until a sending domain is verified in Resend, mail can only be delivered to the email on that Resend account.",
  },
  {
    title: "What does Evaluation show?",
    content:
      "Evaluation measures the correlation engine, not Elasticsearch. Alert reduction is classified events divided by incidents. A campaign is an attacker→victim pair that already has two or more kill-chain phases in the stored events — the same rule the engine uses. Single-phase noise is suppressed and is not counted as a miss. Precision, recall, and F1 use reconstructed incidents as true positives; you can mark extras and misses when you review a run.",
  },
  {
    title: "Glossary",
    content: "",
    glossary: [
      ["Alert reduction", "How many classified events collapse into each incident (events : incidents)."],
      ["C2", "Command & Control — the attacker remotely controls the compromised system."],
      ["Campaign", "An attacker→victim pair whose events span two or more kill-chain phases."],
      ["Correlation", "Grouping phase-tagged events by IP pair so a multi-stage attack is one incident."],
      ["Delivery", "The stage where a payload or exploit is sent to the target."],
      ["ELK", "Elasticsearch, Logstash, and Kibana — used here for collection, not correlation."],
      ["Exploitation", "The stage where the attacker gains access or runs code on the target."],
      ["IDS", "Intrusion Detection System — software that monitors traffic for suspicious activity."],
      ["Incident", "A group of related events that together represent one coordinated attack."],
      ["Kill Chain", "A model that breaks a cyber attack into stages from scanning to remote control."],
      ["Live session", "A Correlate run that keeps polling Elasticsearch for new events."],
      ["Persistence", "When an attacker installs a backdoor or autorun to keep access."],
      ["Reconnaissance", "The first attack stage, where the attacker scans for openings."],
      ["Risk Score", "A 0–100 number from phase breadth, milestones, and attack speed."],
      ["Severity", "Low (0–39), Medium (40–59), High (60–79), or Critical (≥80)."],
      ["Signature", "A Suricata pattern that identifies a specific attack in traffic."],
      ["Suricata", "An open-source network intrusion detection and prevention engine."],
    ],
  },
];

export default function HelpPage() {
  return (
    <>
      <TopBar>
        <ContextTile kicker="reference" title="Help & About" />
      </TopBar>

      <main className="min-h-0 flex-1 overflow-auto p-3">
        <div className="mx-auto flex max-w-[48rem] flex-col gap-2">
          {SECTIONS.map((section) => (
            <Card key={section.title}>
              <CardHeader title={section.title} />
              <CardBody className="p-3">
                {section.content && (
                  <p className="text-[12px] leading-[19px] text-muted">
                    {section.content}
                  </p>
                )}
                {section.glossary && (
                  <div className="flex flex-col gap-1.5">
                    {section.glossary.map(([term, def]) => (
                      <div key={term} className="flex gap-2">
                        <span className="w-32 shrink-0 font-mono text-[11px] font-semibold text-ink">
                          {term}
                        </span>
                        <span className="text-[11px] leading-[17px] text-muted">
                          {def}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </CardBody>
            </Card>
          ))}
        </div>
      </main>
    </>
  );
}
