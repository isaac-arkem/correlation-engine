-- GCTU-SIEM Correlation Engine — Remove duplicated events from the Legacy run
-- Run in your Supabase SQL Editor (Dashboard → SQL Editor → New Query)
--
-- PROBLEM
-- The "Legacy — Initial Experiment" run holds the Suricata capture twice.
-- add_correlation_runs.sql assigned every pre-existing event to the Legacy
-- run, and the capture had been ingested twice before runs existed. `events`
-- has no uniqueness rule, so both copies were kept:
--
--                       eve.json (.2 <-> .3)   Legacy run
--   2026-05-06                 201,290          401,960
--   2026-08-15                 133,638          266,000
--   SimpleHTTP alerts               10               20
--
-- The incident was correlated over one copy (334,457 linked events); only the
-- dashboard totals count both.
--
-- FIX
-- Group identical Suricata rows and keep half of each group (rounded up), so
-- an event that genuinely occurs k times keeps k copies. Rows linked to an
-- incident are never removed: a group keeps at least as many rows as it has
-- linked rows. Windows Security and PowerShell rows are left alone.
--
-- WHY CHUNKS
-- Done in one statement, this outruns the SQL Editor's request
-- ("Failed to fetch (api.supabase.com)"). Step 2a plans one time chunk per
-- call (deciding which ids are extra copies, deleting nothing); step 2b then
-- deletes planned ids in batches of a size you choose. Duplicates share an
-- identical event_time, so a chunk boundary never splits a group. Boundaries
-- were sized from eve.json at ~50k rows each.
--
-- SAFETY
-- * Every call is one statement: it completes, or it rolls back and the same
--   work is redone next call. A chunk is planned exactly once, so re-running
--   cannot halve a group again; a delete batch leaves the plan only together
--   with its rows.
-- * Every removed row is copied to legacy_dedupe_backup first. Step 4 undoes
--   everything.
--
-- HOW TO RUN
--   Step 0, 1, 1b — run once each.
--   Step 2a — run `select dedupe_legacy_plan_next();` until all chunks planned.
--   Step 2b — run `select dedupe_legacy_delete(2000);` until all done.
--   Step 3 — run once: verifies and refreshes the dashboard totals.
--   Step 5 — once you are happy, drop the helper objects.

-- ---------------------------------------------------------------------------
-- STEP 0 — index for the cascade (run once, on its own, before step 2)
-- ---------------------------------------------------------------------------
-- incident_events.event_id references events ON DELETE CASCADE, so deleting
-- an event looks up its links by event_id. The only index is the primary key
-- (incident_id, event_id), which cannot serve that lookup, so every deleted
-- event scanned all of incident_events — this is what timed out. The index
-- also speeds up deleting a whole run, so it is worth keeping afterwards.
create index if not exists idx_incident_events_event on incident_events (event_id);

-- ---------------------------------------------------------------------------
-- STEP 1 — setup (run once)
-- ---------------------------------------------------------------------------
create table if not exists legacy_dedupe_backup (like events);

create table if not exists legacy_dedupe_chunks (
  chunk    int primary key,
  from_ts  timestamptz not null,
  to_ts    timestamptz not null,
  deleted  int,
  done_at  timestamptz
);

-- Consecutive boundaries become [from_ts, to_ts) chunks; the last boundary
-- has no successor, so it only closes the final chunk.
insert into legacy_dedupe_chunks (chunk, from_ts, to_ts)
select chunk, from_ts, to_ts
from (
  select row_number() over (order by b) as chunk,
         b                              as from_ts,
         lead(b) over (order by b)      as to_ts
  from unnest(array[
  '-infinity',
  '2026-05-06T06:05:54Z', '2026-05-06T06:10:06Z', '2026-05-06T06:14:19Z',
  '2026-05-06T06:18:19Z', '2026-05-06T06:18:47Z', '2026-05-06T07:14:04Z',
  '2026-05-06T07:16:54Z', '2026-05-06T14:34:34Z', '2026-08-15T08:57:40Z',
  '2026-08-15T08:57:46Z', '2026-08-15T08:57:53Z', '2026-08-15T09:01:28Z',
  '2026-08-15T09:03:41Z', 'infinity'
  ]::timestamptz[]) as b
) bounds
where to_ts is not null
on conflict (chunk) do nothing;

-- Incident links before any change; step 3 checks this is unchanged.
create table if not exists legacy_dedupe_baseline as
select count(*) as links
from incident_events ie
join incidents i on i.id = ie.incident_id
where i.run_id = '00000000-0000-0000-0000-000000000001';

-- ---------------------------------------------------------------------------
-- STEP 1b — plan + delete helpers (run once; safe to re-run)
-- ---------------------------------------------------------------------------
-- The work is split in two so every call is small and safe to repeat:
--   plan   — per time chunk, list the ids of the extra copies (reads events,
--            deletes nothing). A chunk is planned exactly once.
--   delete — remove a small batch of planned ids, backing each row up first.
--            Re-running after a timeout is harmless: a planned id that is
--            already gone is simply skipped.
drop function if exists dedupe_legacy_next();

create table if not exists legacy_dedupe_plan (
  id    uuid primary key,
  chunk int not null
);

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

create or replace function dedupe_legacy_delete(batch int default 2000) returns text
language plpgsql as $$
declare
  removed int;
  left_n  bigint;
begin
  -- Take a batch off the plan and delete those events in one statement: both
  -- happen or neither does, so a timed-out run leaves the batch in the plan.
  with pick as (
    delete from legacy_dedupe_plan
    where id in (select id from legacy_dedupe_plan limit batch)
    returning id
  ),
  del as (
    delete from events where id in (select id from pick)
    returning *
  )
  insert into legacy_dedupe_backup select * from del;
  get diagnostics removed = row_count;

  select count(*) into left_n from legacy_dedupe_plan;
  return format('Removed %s rows. %s planned rows left%s', removed, left_n,
                case when left_n = 0 then ' — all done, run step 3.' else ' — run it again.' end);
end $$;

-- Helper objects are for the SQL Editor only: keep them off the public API.
alter table legacy_dedupe_backup   enable row level security;
alter table legacy_dedupe_chunks   enable row level security;
alter table legacy_dedupe_baseline enable row level security;
alter table legacy_dedupe_plan     enable row level security;
revoke execute on function dedupe_legacy_plan_next() from public, anon, authenticated;
revoke execute on function dedupe_legacy_delete(int) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- STEP 2a — run repeatedly (14 times) until it says all chunks planned
-- ---------------------------------------------------------------------------
select dedupe_legacy_plan_next();

-- ---------------------------------------------------------------------------
-- STEP 2b — run repeatedly until it says all done. Lower the number if a run
-- times out; raise it if runs finish quickly.
-- ---------------------------------------------------------------------------
select dedupe_legacy_delete(2000);

-- ---------------------------------------------------------------------------
-- STEP 3 — verify and refresh the dashboard totals (run once, after step 2)
-- ---------------------------------------------------------------------------
do $$
declare
  pending   int;
  remaining bigint;
  links     bigint;
  baseline  bigint;
begin
  select count(*) into pending from legacy_dedupe_chunks where done_at is null;
  if pending > 0 then
    raise exception '% chunk(s) not planned yet — keep running step 2a', pending;
  end if;
  select count(*) into pending from legacy_dedupe_plan;
  if pending > 0 then
    raise exception '% planned row(s) not deleted yet — keep running step 2b', pending;
  end if;

  select count(*) into remaining from events
  where run_id = '00000000-0000-0000-0000-000000000001' and source = 'suricata';
  select count(*) into links from incident_events ie
  join incidents i on i.id = ie.incident_id
  where i.run_id = '00000000-0000-0000-0000-000000000001';
  select b.links into baseline from legacy_dedupe_baseline b;

  if links <> baseline then
    raise exception 'Incident links changed (% -> %) — restore with step 4', baseline, links;
  end if;
  if remaining not between 330000 and 336000 then
    raise exception 'Unexpected Suricata count % — check before refreshing; step 4 restores', remaining;
  end if;

  update correlation_runs r
  set event_count   = s.total,
      source_counts = s.by_source,
      phase_counts  = s.by_phase
  from (
    select
      (select count(*) from events
        where run_id = '00000000-0000-0000-0000-000000000001') as total,
      (select coalesce(jsonb_object_agg(source, n), '{}'::jsonb) from (
        select source::text, count(*) as n from events
        where run_id = '00000000-0000-0000-0000-000000000001'
        group by source) x) as by_source,
      (select coalesce(jsonb_object_agg(kill_chain_phase, n), '{}'::jsonb) from (
        select kill_chain_phase, count(*) as n from events
        where run_id = '00000000-0000-0000-0000-000000000001'
          and kill_chain_phase is not null
        group by kill_chain_phase) y) as by_phase
  ) s
  where r.id = '00000000-0000-0000-0000-000000000001';

  raise notice 'OK: % Suricata rows remain, % incident links unchanged', remaining, links;
end $$;

select event_count, source_counts, phase_counts
from correlation_runs
where id = '00000000-0000-0000-0000-000000000001';

-- ---------------------------------------------------------------------------
-- STEP 4 — UNDO (only if something looks wrong): puts every removed row back
-- ---------------------------------------------------------------------------
-- insert into events select * from legacy_dedupe_backup;
-- truncate legacy_dedupe_backup, legacy_dedupe_plan;   -- then redo 2a and 2b
-- update legacy_dedupe_chunks set deleted = null, done_at = null;

-- ---------------------------------------------------------------------------
-- STEP 5 — cleanup, once you are satisfied
-- ---------------------------------------------------------------------------
-- drop function dedupe_legacy_plan_next();
-- drop function dedupe_legacy_delete(int);
-- drop table legacy_dedupe_chunks, legacy_dedupe_baseline, legacy_dedupe_backup,
--            legacy_dedupe_plan;
