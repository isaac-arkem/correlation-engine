import { createSupabaseAdminClient } from '@/lib/supabase/server';
import { resolveAlertRecipient, sendAlertEmail } from '@/lib/notifications/email';

type NotificationType = 'critical' | 'warning' | 'info' | 'success';

export async function createNotification(
  userId: string,
  opts: { type: NotificationType; title: string; message: string; link?: string },
) {
  const sb = createSupabaseAdminClient();
  const { error } = await sb.from('notifications').insert({
    user_id: userId,
    type: opts.type,
    title: opts.title,
    message: opts.message,
    link: opts.link ?? null,
  });

  if (error) {
    console.error('[notifications] Failed to create:', error.message);
    return;
  }

  if (opts.type === 'critical' || opts.type === 'warning') {
    void forwardToEngineer(userId, opts);
  }
}

async function forwardToEngineer(
  userId: string,
  opts: { type: NotificationType; title: string; message: string; link?: string },
) {
  try {
    const sb = createSupabaseAdminClient();
    const { data } = await sb.auth.admin.getUserById(userId);
    const saved = (data.user?.user_metadata?.alert_email as string | undefined)?.trim();
    const fallback = process.env.ALERT_EMAIL?.trim();
    const loginEmail = data.user?.email?.trim();
    const to = resolveAlertRecipient(saved, fallback, loginEmail);
    if (!to) return;

    await sendAlertEmail({
      to,
      type: opts.type,
      title: opts.title,
      message: opts.message,
      link: opts.link,
    });
  } catch (err) {
    console.error('[notifications] forward failed:', err);
  }
}

export async function notifyNewIncidents(
  userId: string,
  runLabel: string,
  incidents: { severity: string; attackerIp: string; victimIp: string }[],
  runId: string,
) {
  if (incidents.length === 0) return;

  const critical = incidents.filter((i) => i.severity === 'critical' || i.severity === 'high');

  if (critical.length > 0) {
    const sb = createSupabaseAdminClient();
    const { data: top } = await sb
      .from('incidents')
      .select('id')
      .eq('run_id', runId)
      .in('severity', ['critical', 'high'])
      .order('risk_score', { ascending: false })
      .limit(1)
      .maybeSingle();

    await createNotification(userId, {
      type: 'critical',
      title: `${critical.length} critical/high incident${critical.length !== 1 ? 's' : ''} detected`,
      message: `Run "${runLabel}" found ${critical.length} high-severity incident${critical.length !== 1 ? 's' : ''}. ${critical[0].attackerIp} → ${critical[0].victimIp}${critical.length > 1 ? ` and ${critical.length - 1} more` : ''}.`,
      link: top?.id ? `/incidents/${top.id}?run=${runId}` : `/?run=${runId}`,
    });
  }

  if (incidents.length > critical.length) {
    const other = incidents.length - critical.length;
    await createNotification(userId, {
      type: 'info',
      title: `${other} additional incident${other !== 1 ? 's' : ''} detected`,
      message: `Run "${runLabel}" detected ${incidents.length} total incidents across the dataset.`,
      link: `/?run=${runId}`,
    });
  }
}

export async function notifyRunCompleted(
  userId: string,
  runLabel: string,
  eventCount: number,
  incidentCount: number,
  runId: string,
) {
  await createNotification(userId, {
    type: 'success',
    title: `Correlation complete: ${runLabel}`,
    message: `${eventCount} events processed, ${incidentCount} incident${incidentCount !== 1 ? 's' : ''} detected.`,
    link: `/?run=${runId}`,
  });
}

export async function notifyLivePollEvent(
  userId: string,
  runLabel: string,
  newEvents: number,
  totalEvents: number,
  runId: string,
) {
  if (newEvents === 0) return;

  await createNotification(userId, {
    type: 'warning',
    title: `${newEvents} new events detected`,
    message: `Live session "${runLabel}" picked up ${newEvents} new events (${totalEvents} total).`,
    link: `/?run=${runId}&live=true`,
  });
}
