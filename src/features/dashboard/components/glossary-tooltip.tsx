"use client";

import { useState, useRef, useEffect, type ReactNode } from "react";

const GLOSSARY: Record<string, string> = {
  reconnaissance:
    "The first stage of an attack where the attacker scans the network to find open ports and vulnerabilities.",
  delivery:
    "The attacker sends malicious files, links, or exploit tools to the target system.",
  exploitation:
    "The attacker uses a vulnerability to gain unauthorized access or run commands on the target.",
  persistence:
    "The attacker installs backdoors or modifies the system so they can return even after a reboot.",
  "command & control":
    "The compromised machine connects back to the attacker so they can control it remotely. Also called C2.",
  c2: "Command & Control — the compromised machine connects back to the attacker for remote control.",
  "kill chain":
    "A model that breaks down a cyber attack into stages: recon, delivery, exploitation, persistence, and command & control.",
  ids: "Intrusion Detection System — software that monitors network traffic for suspicious activity (e.g. Suricata).",
  suricata:
    "An open-source network intrusion detection system (IDS) that inspects traffic for known attack signatures.",
  "risk score":
    "A number from 0–100 measuring how dangerous an incident is. Higher means more attack stages were detected.",
  severity:
    "How serious the incident is: Low (minor scan), Medium (partial attack), High (active exploit), Critical (full compromise).",
  incident:
    "A group of related security events that together represent one coordinated attack.",
  signature:
    "A pattern that identifies a specific type of attack or suspicious activity in network traffic.",
  "powershell":
    "A Windows command-line tool. Attackers often misuse it to run scripts, download malware, or modify system settings.",
  "windows security":
    "Logs from the Windows Event Viewer that record login attempts, privilege changes, and other security events.",
};

export function GlossaryTerm({
  term,
  children,
}: {
  term: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const definition = GLOSSARY[term.toLowerCase()];

  useEffect(() => {
    if (!open) return;
    function close(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  if (!definition) return <>{children}</>;

  return (
    <span ref={ref} className="relative inline-block">
      <span
        className="cursor-help border-b border-dashed border-subtle"
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onClick={() => setOpen(!open)}
      >
        {children}
      </span>
      {open && (
        <span
          className="absolute bottom-full left-1/2 z-50 mb-1.5 w-64 -translate-x-1/2 rounded-lg border border-line bg-field p-2.5 text-[11px] leading-[16px] text-ink shadow-lg"
        >
          <span className="mb-1 block text-[10px] font-bold uppercase tracking-wide text-subtle">
            {term}
          </span>
          {definition}
        </span>
      )}
    </span>
  );
}

export function glossaryInline(text: string): string {
  return text;
}
