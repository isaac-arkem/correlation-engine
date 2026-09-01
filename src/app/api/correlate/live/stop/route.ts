import { NextResponse } from 'next/server';
import { createSupabaseServerClient } from '@/lib/supabase/server';
import { createSupabaseAdminClient } from '@/lib/supabase/server';

export async function POST(request: Request) {
  const supabase = await createSupabaseServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body: { runId: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  if (!body.runId) {
    return NextResponse.json({ error: 'runId is required' }, { status: 400 });
  }

  // Just mark as completed — don't overwrite the counts that poll cycles already wrote
  const sb = createSupabaseAdminClient();
  await sb.from('correlation_runs').update({
    status: 'completed',
    completed_at: new Date().toISOString(),
  }).eq('id', body.runId);

  return NextResponse.json({ ok: true });
}
