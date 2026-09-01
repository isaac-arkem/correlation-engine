'use server';

import { createSupabaseServerClient } from '@/lib/supabase/server';
import { createSupabaseAdminClient } from '@/lib/supabase/server';
import {
  canSendAlertEmail,
  isValidEmail,
  resolveAlertRecipient,
  sendAlertEmail,
} from '@/lib/notifications/email';

export interface Notification {
  id: string;
  type: 'critical' | 'warning' | 'info' | 'success';
  title: string;
  message: string;
  link: string | null;
  read: boolean;
  createdAt: string;
}

export async function getNotifications(): Promise<{ notifications: Notification[]; unreadCount: number }> {
  const supabase = await createSupabaseServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { notifications: [], unreadCount: 0 };

  const sb = createSupabaseAdminClient();

  const { data } = await sb
    .from('notifications')
    .select('*')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false })
    .limit(30);

  const rows = data ?? [];
  const unreadCount = rows.filter((r) => !r.read).length;

  return {
    notifications: rows.map((r) => ({
      id: r.id,
      type: r.type as Notification['type'],
      title: r.title,
      message: r.message,
      link: r.link,
      read: r.read,
      createdAt: r.created_at,
    })),
    unreadCount,
  };
}

export async function markAsRead(notificationId: string): Promise<void> {
  const supabase = await createSupabaseServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return;

  const sb = createSupabaseAdminClient();
  await sb.from('notifications').update({ read: true }).eq('id', notificationId).eq('user_id', user.id);
}

export async function getAlertSettings(): Promise<{
  email: string;
  emailEnabled: boolean;
}> {
  const supabase = await createSupabaseServerClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const saved = (user?.user_metadata?.alert_email as string | undefined)?.trim() ?? "";
  const fallback = process.env.ALERT_EMAIL?.trim() ?? "";
  const loginEmail = user?.email?.trim() ?? "";

  return {
    email: resolveAlertRecipient(saved, fallback, loginEmail),
    emailEnabled: canSendAlertEmail(),
  };
}

export async function saveAlertEmail(
  email: string,
): Promise<{ ok: boolean; error?: string }> {
  const trimmed = email.trim();
  if (trimmed && !isValidEmail(trimmed)) {
    return { ok: false, error: "Enter a valid email address." };
  }

  const supabase = await createSupabaseServerClient();
  const { error } = await supabase.auth.updateUser({
    data: { alert_email: trimmed },
  });

  if (error) return { ok: false, error: error.message };
  return { ok: true };
}

export async function forwardNotification(
  notificationId: string,
  toOverride?: string,
  origin?: string,
): Promise<{ ok: boolean; sentTo?: string; error?: string }> {
  const supabase = await createSupabaseServerClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "Not signed in." };

  const settings = await getAlertSettings();
  const to = resolveAlertRecipient(toOverride, settings.email);
  if (!to) {
    return { ok: false, error: "Set an engineer email first." };
  }

  const sb = createSupabaseAdminClient();
  const { data: row } = await sb
    .from("notifications")
    .select("id, type, title, message, link")
    .eq("id", notificationId)
    .eq("user_id", user.id)
    .single();

  if (!row) return { ok: false, error: "Notification not found." };

  return sendAlertEmail({
    to,
    type: row.type,
    title: row.title,
    message: row.message,
    link: row.link,
    origin,
  });
}

export async function markAllAsRead(): Promise<void> {
  const supabase = await createSupabaseServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return;

  const sb = createSupabaseAdminClient();
  await sb.from('notifications').update({ read: true }).eq('user_id', user.id).eq('read', false);
}
