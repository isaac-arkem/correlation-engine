import type { IncidentStatus } from "../actions";

interface Action {
  title: string;
  description: string;
  urgent: boolean;
}

const ACTIONS: Record<IncidentStatus, Action[]> = {
  new: [
    {
      title: "Review the incident summary",
      description:
        "Read the summary and timeline to understand what happened. Check which systems were affected.",
      urgent: true,
    },
    {
      title: "Assign an analyst",
      description:
        'Change the status to "Investigating" and assign a team member to handle this incident.',
      urgent: true,
    },
    {
      title: "Notify stakeholders",
      description:
        "Inform your manager or security team lead about the detected incident.",
      urgent: false,
    },
  ],
  investigating: [
    {
      title: "Isolate affected systems",
      description:
        "Disconnect the victim host from the network to prevent further damage or data exfiltration.",
      urgent: true,
    },
    {
      title: "Collect evidence",
      description:
        "Take disk images and memory dumps from affected systems before making changes. Export the PDF report for records.",
      urgent: true,
    },
    {
      title: "Check for lateral movement",
      description:
        "Look for signs that the attacker moved to other systems on your network beyond the identified victim.",
      urgent: false,
    },
    {
      title: "Block attacker IP",
      description:
        "Add the attacker IP address to your firewall block list to prevent further access.",
      urgent: false,
    },
  ],
  resolved: [
    {
      title: "Document the incident",
      description:
        "Write a post-incident report covering what happened, how it was detected, and what was done to fix it.",
      urgent: false,
    },
    {
      title: "Update firewall rules",
      description:
        "Review and update your firewall and IDS rules based on the attack signatures observed.",
      urgent: false,
    },
    {
      title: "Patch vulnerabilities",
      description:
        "Apply security patches to the victim system to prevent the same exploit from working again.",
      urgent: false,
    },
    {
      title: "Schedule a review",
      description:
        "Hold a lessons-learned meeting with the team to improve detection and response for next time.",
      urgent: false,
    },
  ],
  false_positive: [
    {
      title: "No action required",
      description:
        "This incident has been marked as a false positive. The correlated events were not part of an actual attack.",
      urgent: false,
    },
    {
      title: "Review classification rules",
      description:
        "Consider whether the rules that flagged these events need tuning to reduce future false positives.",
      urgent: false,
    },
    {
      title: "Document the dismissal",
      description:
        "Note why this was a false positive so the team can recognise similar patterns in future.",
      urgent: false,
    },
  ],
};

export function RecommendedActions({ status }: { status: IncidentStatus }) {
  const actions = ACTIONS[status] ?? ACTIONS.new;

  return (
    <div className="flex flex-col gap-1.5">
      {actions.map((action, i) => (
        <div
          key={i}
          className="rounded-md border px-2.5 py-2"
          style={{
            borderColor: action.urgent ? "#4d3f22" : "#262626",
            background: action.urgent ? "#1f1c14" : "transparent",
          }}
        >
          <div className="flex items-center gap-1.5">
            {action.urgent && (
              <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
            )}
            <span className="text-[11px] font-semibold text-ink">
              {action.title}
            </span>
          </div>
          <p className="mt-0.5 text-[10px] leading-[15px] text-muted">
            {action.description}
          </p>
        </div>
      ))}
    </div>
  );
}
