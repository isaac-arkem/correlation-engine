"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, useTransition } from "react";

import { cn } from "@/lib/utils/cn";
import {
  getSavedConnections,
  saveConnection,
  deleteConnection,
} from "@/features/correlate/actions";

type SavedConn = Awaited<ReturnType<typeof getSavedConnections>>[number];

export function LiveForm() {
  const router = useRouter();
  const [label, setLabel] = useState("");
  const [connectMode, setConnectMode] = useState<"url" | "cloud">("cloud");
  const [esUrl, setEsUrl] = useState("");
  const [cloudId, setCloudId] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [suricataIndex, setSuricataIndex] = useState("filebeat-*");
  const [winlogIndex, setWinlogIndex] = useState("winlogbeat-*");
  const [pollInterval, setPollInterval] = useState(30);
  const [maxPolls, setMaxPolls] = useState(10);

  const [status, setStatus] = useState<"idle" | "connecting" | "error">("idle");
  const [error, setError] = useState<string | null>(null);

  // Saved connections
  const [saved, setSaved] = useState<SavedConn[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [saveLabel, setSaveLabel] = useState("");
  const [showSave, setShowSave] = useState(false);
  const [isPending, startTransition] = useTransition();

  useEffect(() => {
    getSavedConnections().then((conns) => {
      setSaved(conns);
      if (conns.length > 0) {
        setSelectedId(conns[0].id);
        applyConnection(conns[0]);
      }
    });
  }, []);

  function applyConnection(conn: SavedConn) {
    setConnectMode(conn.connect_mode as "url" | "cloud");
    setEsUrl(conn.es_url ?? "");
    setCloudId(conn.cloud_id ?? "");
    setApiKey(conn.api_key ?? "");
    setSuricataIndex(conn.suricata_index);
    setWinlogIndex(conn.winlog_index);
    setPollInterval(conn.poll_interval);
    setMaxPolls(conn.max_polls);
  }

  function handleSelect(id: string) {
    setSelectedId(id);
    const conn = saved.find((c) => c.id === id);
    if (conn) applyConnection(conn);
  }

  function handleSave() {
    if (!saveLabel.trim()) return;
    startTransition(async () => {
      await saveConnection({
        label: saveLabel.trim(),
        connectMode,
        esUrl,
        cloudId,
        apiKey,
        suricataIndex,
        winlogIndex,
        pollInterval,
        maxPolls,
      });
      const updated = await getSavedConnections();
      setSaved(updated);
      setSelectedId(updated[0]?.id ?? "");
      setSaveLabel("");
      setShowSave(false);
    });
  }

  function handleDelete(id: string) {
    startTransition(async () => {
      await deleteConnection(id);
      const updated = await getSavedConnections();
      setSaved(updated);
      if (selectedId === id) {
        setSelectedId(updated[0]?.id ?? "");
        if (updated[0]) applyConnection(updated[0]);
      }
    });
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStatus("connecting");
    setError(null);

    // If user filled fields but hasn't saved yet, save first
    let connectionId = selectedId;
    if (!connectionId) {
      try {
        await saveConnection({
          label: label.trim() || "Untitled",
          connectMode,
          esUrl,
          cloudId,
          apiKey,
          suricataIndex,
          winlogIndex,
          pollInterval,
          maxPolls,
        });
        const updated = await getSavedConnections();
        setSaved(updated);
        connectionId = updated[0]?.id ?? "";
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to save connection");
        setStatus("error");
        return;
      }
    }

    try {
      const res = await fetch("/api/correlate/live/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: label.trim(),
          connectionId,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Failed to start");

      router.push(`/?run=${data.runId}&live=true`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setStatus("error");
    }
  }

  const hasConnection =
    connectMode === "cloud"
      ? cloudId.trim().length > 0
      : esUrl.trim().length > 0;
  const canSubmit =
    status !== "connecting" && label.trim().length > 0 && hasConnection;

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-6">
      {/* Saved connections selector */}
      {saved.length > 0 && (
        <div className="flex flex-col gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-muted">
            Saved Connections
          </span>
          <div className="flex flex-wrap gap-2">
            {saved.map((conn) => (
              <div key={conn.id} className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => handleSelect(conn.id)}
                  className={cn(
                    "rounded-md px-3 py-1.5 text-[11px] font-medium transition-colors",
                    selectedId === conn.id
                      ? "bg-accent/20 text-accent ring-1 ring-accent/40"
                      : "bg-line text-subtle hover:text-ink"
                  )}
                >
                  {conn.label}
                </button>
                <button
                  type="button"
                  onClick={() => handleDelete(conn.id)}
                  disabled={isPending}
                  className="text-[10px] text-subtle hover:text-red-400"
                  title="Delete"
                >
                  &times;
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      <fieldset
        disabled={status === "connecting"}
        className="flex flex-col gap-4"
      >
        <Field label="Session Label" required>
          <input
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="e.g. Live monitoring — Aug 31"
            className={INPUT}
          />
        </Field>

        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setConnectMode("cloud")}
            className={cn(
              "rounded-md px-3 py-1 text-[10px] font-semibold transition-colors",
              connectMode === "cloud"
                ? "bg-accent/20 text-accent"
                : "bg-line text-subtle hover:text-muted"
            )}
          >
            Elastic Cloud
          </button>
          <button
            type="button"
            onClick={() => setConnectMode("url")}
            className={cn(
              "rounded-md px-3 py-1 text-[10px] font-semibold transition-colors",
              connectMode === "url"
                ? "bg-accent/20 text-accent"
                : "bg-line text-subtle hover:text-muted"
            )}
          >
            Self-hosted URL
          </button>
        </div>

        {connectMode === "cloud" ? (
          <Field label="Cloud ID" required>
            <input
              type="text"
              value={cloudId}
              onChange={(e) => setCloudId(e.target.value)}
              placeholder="My_deployment:dXMtY2VudHJhbDEuZ2Nw..."
              className={INPUT}
            />
          </Field>
        ) : (
          <Field label="Elasticsearch URL" required>
            <input
              type="text"
              value={esUrl}
              onChange={(e) => setEsUrl(e.target.value)}
              placeholder="http://localhost:9200"
              className={INPUT}
            />
          </Field>
        )}

        <Field label="API Key">
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="From Kibana → Stack Management → API Keys"
            className={INPUT}
          />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Suricata Index">
            <input
              type="text"
              value={suricataIndex}
              onChange={(e) => setSuricataIndex(e.target.value)}
              placeholder="filebeat-*"
              className={INPUT}
            />
          </Field>
          <Field label="Winlogbeat Index">
            <input
              type="text"
              value={winlogIndex}
              onChange={(e) => setWinlogIndex(e.target.value)}
              placeholder="winlogbeat-*"
              className={INPUT}
            />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Poll Interval (seconds)">
            <input
              type="number"
              min={10}
              max={120}
              value={pollInterval}
              onChange={(e) => setPollInterval(Number(e.target.value))}
              className={INPUT}
            />
          </Field>
          <Field label="Max Polls">
            <input
              type="number"
              min={1}
              max={60}
              value={maxPolls}
              onChange={(e) => setMaxPolls(Number(e.target.value))}
              className={INPUT}
            />
          </Field>
        </div>

        <p className="text-[10px] text-subtle">
          The engine polls every {pollInterval}s for up to {maxPolls} cycles (
          {Math.round((pollInterval * maxPolls) / 60)} min). You can watch
          progress on the dashboard.
        </p>
      </fieldset>

      {/* Save connection button */}
      <div className="flex flex-col gap-2">
        {showSave ? (
          <div className="flex items-end gap-2">
            <label className="flex flex-1 flex-col gap-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-muted">
                Connection Name
              </span>
              <input
                type="text"
                value={saveLabel}
                onChange={(e) => setSaveLabel(e.target.value)}
                placeholder="e.g. GCTU Lab ELK"
                className={INPUT}
              />
            </label>
            <button
              type="button"
              onClick={handleSave}
              disabled={!saveLabel.trim() || isPending}
              className="rounded-md bg-line px-3 py-1.5 text-[11px] font-semibold text-ink hover:opacity-80 disabled:opacity-50"
            >
              {isPending ? "Saving…" : "Save"}
            </button>
            <button
              type="button"
              onClick={() => setShowSave(false)}
              className="rounded-md px-2 py-1.5 text-[11px] text-subtle hover:text-ink"
            >
              Cancel
            </button>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setShowSave(true)}
            className="w-fit text-[11px] text-accent hover:underline"
          >
            Save this connection for later
          </button>
        )}
      </div>

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
        {status === "connecting" ? "Connecting…" : "Start Live Session"}
      </button>
    </form>
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
