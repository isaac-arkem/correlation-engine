"use client";

import { useRouter } from "next/navigation";
import { useRef, useState } from "react";

import { cn } from "@/lib/utils/cn";
import {
  detectLogTypeFromText,
  LOG_TYPE_LABELS,
  type LogType,
} from "@/lib/correlation/detect";

interface DetectedFile {
  file: File;
  type: LogType;
}

interface CorrelateResult {
  runId: string;
  label: string;
  eventCount: number;
  incidentCount: number;
}

interface DetectedConfig {
  attackerIps: string[];
  victimIps: string[];
  c2Ports: number[];
}

interface ProgressEvent {
  step: string;
  message: string;
  progress: number;
  detected?: DetectedConfig;
  result?: CorrelateResult;
  file?: string;
  fileIndex?: number;
  fileCount?: number;
  eventsParsed?: number;
  totalEvents?: number;
  classifiedCount?: number;
  incidentCount?: number;
}

const STEP_LABELS: Record<string, string> = {
  parsing: "Parsing log files",
  parsed: "Parsing log files",
  detecting: "Auto-detecting IPs & ports",
  detected: "Auto-detecting IPs & ports",
  classifying: "Kill chain classification",
  classified: "Kill chain classification",
  correlating: "Incident correlation",
  correlated: "Incident correlation",
  persisting: "Saving to database",
  done: "Complete",
};

export function CorrelateForm() {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<DetectedFile[]>([]);
  const [status, setStatus] = useState<
    "idle" | "running" | "success" | "error"
  >("idle");
  const [result, setResult] = useState<CorrelateResult | null>(null);
  const [detected, setDetected] = useState<DetectedConfig | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  const [progress, setProgress] = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [currentStep, setCurrentStep] = useState("");

  async function handleFilesSelected(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = Array.from(e.target.files ?? []);
    if (!selected.length) return;

    const detectedFiles: DetectedFile[] = [];
    for (const file of selected) {
      const head = await file.slice(0, 8192).text();
      const type = detectLogTypeFromText(head, file.name);
      detectedFiles.push({ file, type });
    }

    setFiles((prev) => [...prev, ...detectedFiles]);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function removeFile(index: number) {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  }

  function changeType(index: number, type: LogType) {
    setFiles((prev) =>
      prev.map((f, i) => (i === index ? { ...f, type } : f))
    );
  }

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setStatus("running");
    setError(null);
    setResult(null);
    setDetected(null);
    setProgress(0);
    setProgressMsg("Preparing upload…");
    setCurrentStep("");

    const form = e.currentTarget;
    const formData = new FormData(form);

    formData.delete("fileInput");
    const validFiles = files.filter((f) => f.type !== "unknown");
    if (validFiles.length === 0) {
      setError("Add at least one recognized log file");
      setStatus("error");
      return;
    }

    for (let i = 0; i < validFiles.length; i++) {
      formData.append("files", validFiles[i].file);
      formData.append("types", validFiles[i].type);
    }

    try {
      const res = await fetch("/api/correlate", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const text = await res.text();
        let msg = "Correlation failed";
        try { msg = JSON.parse(text).error ?? msg; } catch {}
        throw new Error(msg);
      }

      const reader = res.body?.getReader();
      if (!reader) throw new Error("No response stream");

      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const evt: ProgressEvent = JSON.parse(line);
            setProgress(evt.progress);
            setProgressMsg(evt.message);
            setCurrentStep(evt.step);

            if (evt.detected) {
              setDetected(evt.detected);
            }

            if (evt.step === "done" && evt.result) {
              setResult(evt.result);
              setStatus("success");
              setTimeout(() => {
                router.push(`/?run=${evt.result!.runId}`);
              }, 3000);
            }

            if (evt.step === "error") {
              throw new Error(evt.message);
            }
          } catch (parseErr) {
            if (parseErr instanceof Error && parseErr.message !== line) {
              throw parseErr;
            }
          }
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setStatus("error");
    }
  }

  const isRunning = status === "running";
  const canSubmit =
    !isRunning &&
    label.trim().length > 0 &&
    files.filter((f) => f.type !== "unknown").length > 0;

  return (
    <form
      ref={formRef}
      onSubmit={handleSubmit}
      className="flex flex-col gap-6"
    >
      <fieldset disabled={isRunning} className="flex flex-col gap-6">
        <Field label="Dataset Label" required>
          <input
            name="label"
            type="text"
            required
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="e.g. Experiment 2 — extended capture"
            className={cn(INPUT)}
          />
        </Field>

        <div className="flex flex-col gap-3">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-muted">
            Log Files
          </span>

          {files.length > 0 && (
            <div className="flex flex-col gap-1.5">
              {files.map((f, i) => (
                <div
                  key={`${f.file.name}-${i}`}
                  className="flex items-center gap-2 rounded-md border border-line bg-base px-3 py-2"
                >
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink">
                    {f.file.name}
                  </span>
                  <span className="text-[10px] text-subtle">
                    {(f.file.size / 1024).toFixed(0)} KB
                  </span>
                  <select
                    value={f.type}
                    onChange={(e) => changeType(i, e.target.value as LogType)}
                    className="rounded border border-line bg-field px-1.5 py-0.5 text-[10px] text-ink"
                  >
                    <option value="suricata">Suricata EVE</option>
                    <option value="windows_security">Windows Security</option>
                    <option value="powershell">PowerShell</option>
                    <option value="unknown">Unknown</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => removeFile(i)}
                    className="text-[11px] text-subtle hover:text-red-400"
                  >
                    ✕
                  </button>
                </div>
              ))}
            </div>
          )}

          <label
            className={cn(
              "flex cursor-pointer flex-col items-center gap-1 rounded-md border border-dashed border-line bg-base px-4 py-6",
              "text-[11px] text-subtle",
              "hover:border-line-strong hover:text-muted",
              "transition-colors"
            )}
          >
            <span className="text-[12px] font-medium text-muted">
              + Add log files
            </span>
            <span className="text-[10px]">
              JSON, CSV — auto-detected as Suricata, Windows Security, or
              PowerShell
            </span>
            <input
              ref={fileInputRef}
              name="fileInput"
              type="file"
              multiple
              accept=".json,.csv,.log,.txt"
              onChange={handleFilesSelected}
              className="hidden"
            />
          </label>
        </div>

        <p className="text-[10px] text-subtle">
          Attacker IPs, victim IPs, and C2 ports are auto-detected from the
          uploaded logs.
        </p>
      </fieldset>

      {/* Progress gauge */}
      {isRunning && (
        <div className="flex flex-col gap-2 rounded-md border border-line bg-base px-4 py-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-ink">
              {STEP_LABELS[currentStep] ?? "Processing…"}
            </span>
            <span className="font-mono text-[11px] font-semibold text-accent">
              {progress}%
            </span>
          </div>

          <div className="relative h-2 overflow-hidden rounded-full bg-line">
            <div
              className="absolute inset-y-0 left-0 rounded-full bg-accent transition-all duration-500 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>

          <p className="text-[10px] text-subtle">{progressMsg}</p>

          {/* Step checklist */}
          <div className="mt-1 flex flex-col gap-1">
            {renderStepItem("parsing", "Parse log files", currentStep, progress)}
            {renderStepItem("detecting", "Auto-detect IPs & ports", currentStep, progress)}
            {renderStepItem("classifying", "Kill chain classification", currentStep, progress)}
            {renderStepItem("correlating", "Incident correlation", currentStep, progress)}
            {renderStepItem("persisting", "Save to database", currentStep, progress)}
          </div>
        </div>
      )}

      {/* Success result + detected config */}
      {status === "success" && result && (
        <div className="flex flex-col gap-3 rounded-md border border-green-500/30 bg-green-500/5 px-4 py-4">
          <div className="flex items-center gap-2">
            <span className="text-[14px]">&#10003;</span>
            <span className="text-[12px] font-semibold text-green-500">
              Correlation Complete
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Stat label="Events classified" value={result.eventCount.toLocaleString()} />
            <Stat label="Incidents detected" value={String(result.incidentCount)} />
          </div>

          {detected && (
            <div className="flex flex-col gap-2 border-t border-green-500/20 pt-3">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-muted">
                Auto-Detected Configuration
              </span>
              <div className="grid gap-2 sm:grid-cols-3">
                <ConfigPill
                  label="Attacker IPs"
                  values={detected.attackerIps}
                  empty="none found"
                />
                <ConfigPill
                  label="Victim IPs"
                  values={detected.victimIps}
                  empty="none found"
                />
                <ConfigPill
                  label="C2 Ports"
                  values={detected.c2Ports.map(String)}
                  empty="none found"
                />
              </div>
            </div>
          )}

          <p className="text-[10px] text-green-500/70">
            Redirecting to dashboard…
          </p>
        </div>
      )}

      {status === "error" && error && (
        <div className="rounded-md border border-red-500/30 bg-red-500/5 px-4 py-3">
          <p className="text-[11px] text-red-400">{error}</p>
        </div>
      )}

      <button
        type="submit"
        disabled={!canSubmit}
        className={cn(
          "w-fit rounded-md bg-accent px-5 py-2 text-[12px] font-semibold text-inverse",
          "hover:opacity-90 disabled:opacity-50"
        )}
      >
        {isRunning ? "Running correlation…" : "Run Correlation"}
      </button>
    </form>
  );
}

/* ── helpers ─────────────────────────────────────────── */

const STEP_ORDER = ["parsing", "detecting", "classifying", "correlating", "persisting"];
const STEP_DONE_AFTER: Record<string, number> = {
  parsing: 35,
  detecting: 48,
  classifying: 60,
  correlating: 72,
  persisting: 100,
};

function renderStepItem(
  step: string,
  label: string,
  currentStep: string,
  progress: number
) {
  const stepIdx = STEP_ORDER.indexOf(step);
  const currentIdx = STEP_ORDER.indexOf(currentStep);
  const doneThreshold = STEP_DONE_AFTER[step] ?? 100;

  const isDone = progress >= doneThreshold;
  const isActive = !isDone && currentIdx === stepIdx;

  return (
    <div className="flex items-center gap-2">
      <span
        className={cn(
          "flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-[8px] font-bold",
          isDone
            ? "bg-green-500/20 text-green-500"
            : isActive
              ? "bg-accent/20 text-accent"
              : "bg-line text-subtle"
        )}
      >
        {isDone ? "✓" : stepIdx + 1}
      </span>
      <span
        className={cn(
          "text-[10px]",
          isDone ? "text-green-500" : isActive ? "text-ink" : "text-subtle"
        )}
      >
        {label}
      </span>
      {isActive && (
        <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] text-muted">{label}</span>
      <span className="font-mono text-[14px] font-bold text-ink">{value}</span>
    </div>
  );
}

function ConfigPill({
  label,
  values,
  empty,
}: {
  label: string;
  values: string[];
  empty: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[9px] font-semibold uppercase tracking-wider text-muted">
        {label}
      </span>
      {values.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {values.map((v) => (
            <span
              key={v}
              className="rounded bg-green-500/10 px-1.5 py-0.5 font-mono text-[10px] text-green-500"
            >
              {v}
            </span>
          ))}
        </div>
      ) : (
        <span className="text-[10px] italic text-subtle">{empty}</span>
      )}
    </div>
  );
}

const INPUT =
  "w-full rounded-md border border-line bg-field px-2.5 py-1.5 font-mono text-[11px] text-ink outline-none placeholder:text-subtle focus:border-line-strong";

function Field({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] font-semibold uppercase tracking-wider text-muted">
        {label}
        {required && <span className="text-red-400"> *</span>}
      </span>
      {children}
    </label>
  );
}
