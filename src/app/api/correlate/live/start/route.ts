import { NextResponse } from 'next/server';
import { createSupabaseServerClient } from '@/lib/supabase/server';
import { Client } from '@elastic/elasticsearch';
import { createRun } from '@/lib/correlation/persist';

export async function POST(request: Request) {
  const supabase = await createSupabaseServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body: { label: string; connectionId: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const { label, connectionId } = body;

  if (!label?.trim()) {
    return NextResponse.json({ error: 'A session label is required' }, { status: 400 });
  }
  if (!connectionId) {
    return NextResponse.json({ error: 'A saved connection is required' }, { status: 400 });
  }

  // Look up the connection from DB
  const { data: conn, error: connErr } = await supabase
    .from('es_connections')
    .select('*')
    .eq('id', connectionId)
    .eq('user_id', user.id)
    .single();

  if (connErr || !conn) {
    return NextResponse.json({ error: 'Connection not found' }, { status: 404 });
  }

  // Test the connection
  const clientOpts: Record<string, unknown> = {};
  if (conn.cloud_id) {
    clientOpts.cloud = { id: conn.cloud_id };
  } else if (conn.es_url) {
    clientOpts.node = conn.es_url;
  } else {
    return NextResponse.json({ error: 'Connection has no URL or Cloud ID' }, { status: 400 });
  }
  if (conn.api_key) {
    clientOpts.auth = { apiKey: conn.api_key };
  }

  try {
    const client = new Client(clientOpts as ConstructorParameters<typeof Client>[0]);
    await client.ping();
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Connection failed';
    return NextResponse.json({ error: `Cannot connect to Elasticsearch: ${msg}` }, { status: 400 });
  }

  // Create the run linked to the connection
  const runId = await createRun({
    label: label.trim(),
    sourceType: 'elasticsearch',
    attackerIps: [],
    victimIps: [],
    c2Ports: [],
    connectionId,
  });

  return NextResponse.json({ runId });
}
