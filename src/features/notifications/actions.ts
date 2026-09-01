'use server';

import { createSupabaseServerClient } from '@/lib/supabase/server';
import { createSupabaseAdminClient } from '@/lib/supabase/server';

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

export async function markAllAsRead(): Promise<void> {
  const supabase = await createSupabaseServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return;

  const sb = createSupabaseAdminClient();
  await sb.from('notifications').update({ read: true }).eq('user_id', user.id).eq('read', false);
}
