import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { ContextTile, TopBar } from "@/components/ui/top-bar";

const SECTIONS = [
  {
    title: "What is GCTU-SIEM?",
    content:
      "GCTU-SIEM is a lightweight Security Information and Event Management system built for small and medium enterprises. It collects security logs from multiple sources, classifies events using a kill-chain model, and automatically correlates them into actionable incidents. This helps you detect cyber attacks early without needing a dedicated security operations team.",
  },
  {
    title: "How does it work?",
    content:
      "The system works in four steps: (1) Ingestion — log files from your network sensors and systems are imported and parsed. (2) Classification — each event is assigned a kill-chain phase based on its type and content. (3) Correlation — related events are grouped into incidents based on attacker-victim pairs and timing. (4) Presentation — incidents are displayed on this dashboard with severity scores, timelines, and recommended actions.",
  },
  {
    title: "What is the kill chain?",
    content:
      "The Cyber Kill Chain is a model that breaks down a cyber attack into five stages. Reconnaissance: the attacker scans your network looking for weaknesses. Delivery: malicious payloads are sent to your systems. Exploitation: vulnerabilities are used to gain unauthorized access. Persistence: the attacker installs backdoors to maintain access. Command & Control (C2): the compromised system communicates with the attacker for remote control. The more stages detected, the more serious the attack.",
  },
  {
    title: "What does the risk score mean?",
    content:
      "The risk score ranges from 0 to 100 and measures how dangerous an incident is. It increases based on how many kill-chain phases are detected and how advanced they are. 0–30 is Low (minor scanning activity), 31–50 is Medium (partial attack, possibly automated), 51–70 is High (active exploitation detected), and 71–100 is Critical (full multi-stage compromise requiring immediate action).",
  },
  {
    title: "What are the data sources?",
    content:
      "The system can ingest logs from any source. Common sources include: Suricata — an open-source network intrusion detection system that monitors traffic for known attack patterns. Windows Security Logs — events from Windows Event Viewer recording logins, privilege changes, and policy modifications. PowerShell Logs — records of commands and scripts executed on Windows systems, often misused by attackers. New sources can be added by providing log files in the supported formats.",
  },
  {
    title: "What should I do when an incident is detected?",
    content:
      "When a new incident appears: (1) Read the 'What happened' summary to understand the situation. (2) Check the risk score gauge — Critical incidents need immediate attention. (3) Follow the 'Recommended actions' panel, which provides step-by-step guidance based on the incident status. (4) Change the status to 'Investigating' when you start working on it. (5) Export a PDF report for your records. (6) Mark as 'Resolved' when the issue is addressed.",
  },
  {
    title: "How do I add new log data?",
    content:
      "To analyze new logs, place your log files in the configured data directory and run the correlation engine. The engine will automatically parse the files, classify events, correlate them into incidents, and update the dashboard. Supported formats include JSON (for Suricata EVE logs) and CSV (for Windows Event Viewer and PowerShell exports).",
  },
  {
    title: "Glossary",
    content: "",
    glossary: [
      ["C2", "Command & Control — the attacker remotely controls the compromised system."],
      ["IDS", "Intrusion Detection System — software that monitors network traffic for suspicious activity."],
      ["Incident", "A group of related security events that together represent one coordinated attack."],
      ["Kill Chain", "A model that breaks a cyber attack into stages from initial scanning to full compromise."],
      ["Persistence", "When an attacker installs backdoors to maintain access even after the system is rebooted."],
      ["Reconnaissance", "The first attack stage where the attacker scans for open ports and vulnerabilities."],
      ["Risk Score", "A 0–100 number measuring incident severity based on detected kill-chain phases."],
      ["Severity", "Low, Medium, High, or Critical — how serious the incident is."],
      ["Signature", "A pattern that identifies a specific type of attack in network traffic."],
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

      <main className="flex-1 overflow-auto p-3">
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
                        <span className="w-28 shrink-0 font-mono text-[11px] font-semibold text-ink">
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
