create index if not exists idx_incident_events_event on incident_events (event_id);

create or replace function dedupe_legacy_plan_next() returns text
language plpgsql
-- The default 4MB is too small to hash 334k link ids, which made Postgres
-- re-scan incident_events once per event.
set work_mem = '64MB'
as $$
declare
  c       legacy_dedupe_chunks;
  planned int;
  left_n  int;
begin
  select * into c from legacy_dedupe_chunks
  where done_at is null order by chunk limit 1 for update;
  if not found then
    return 'All chunks planned — now run step 2b.';
  end if;

  insert into legacy_dedupe_plan (id, chunk)
  select id, c.chunk
  from (
    select e.id,
           row_number() over (g order by linked desc, e.id) as rn,
           count(*)     over g                               as n,
           count(*) filter (where linked) over g             as n_linked
    from (
      select ev.id, ev.event_time, ev.event_type, ev.event_id, ev.src_ip,
             ev.dest_ip, ev.src_port, ev.dest_port, ev.proto, ev.signature,
             ev.category, ev.message, ev.kill_chain_phase,
             exists (select 1 from incident_events ie where ie.event_id = ev.id) as linked
      from events ev
      where ev.run_id = '00000000-0000-0000-0000-000000000001'
        and ev.source = 'suricata'
        and ev.event_time >= c.from_ts
        and ev.event_time <  c.to_ts
    ) e
    window g as (
      partition by e.event_time, e.event_type, e.event_id, e.src_ip, e.dest_ip,
                   e.src_port, e.dest_port, e.proto, e.signature, e.category,
                   e.message, e.kill_chain_phase
    )
  ) ranked
  where rn > greatest(ceil(n / 2.0), n_linked)
  on conflict (id) do nothing;
  get diagnostics planned = row_count;

  update legacy_dedupe_chunks set deleted = planned, done_at = now()
  where chunk = c.chunk;

  select count(*) into left_n from legacy_dedupe_chunks where done_at is null;
  return format('Chunk %s planned: %s duplicate rows to remove. %s chunk(s) left to plan.',
                c.chunk, planned, left_n);
end $$;

revoke execute on function dedupe_legacy_plan_next() from public, anon, authenticated;
