"use server";

import { createSupabaseServerClient } from "@/lib/supabase/server";

export async function getSavedConnections() {
  const sb = await createSupabaseServerClient();
  const {
    data: { user },
  } = await sb.auth.getUser();
  if (!user) return [];

  const { data } = await sb
    .from("es_connections")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  return data ?? [];
}

export async function saveConnection(form: {
  label: string;
  connectMode: "cloud" | "url";
  esUrl?: string;
  cloudId?: string;
  apiKey?: string;
  suricataIndex: string;
  winlogIndex: string;
  pollInterval: number;
  maxPolls: number;
}) {
  const sb = await createSupabaseServerClient();
  const {
    data: { user },
  } = await sb.auth.getUser();
  if (!user) throw new Error("Unauthorized");

  const { error } = await sb.from("es_connections").insert({
    user_id: user.id,
    label: form.label.trim(),
    connect_mode: form.connectMode,
    es_url: form.esUrl?.trim() || null,
    cloud_id: form.cloudId?.trim() || null,
    api_key: form.apiKey?.trim() || null,
    suricata_index: form.suricataIndex.trim(),
    winlog_index: form.winlogIndex.trim(),
    poll_interval: form.pollInterval,
    max_polls: form.maxPolls,
  });

  if (error) throw new Error(error.message);
}

export async function deleteConnection(id: string) {
  const sb = await createSupabaseServerClient();
  const {
    data: { user },
  } = await sb.auth.getUser();
  if (!user) throw new Error("Unauthorized");

  await sb.from("es_connections").delete().eq("id", id).eq("user_id", user.id);
}
