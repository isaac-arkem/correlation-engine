-- GCTU-SIEM Correlation Engine — Dashboard performance
-- Run this in your Supabase SQL Editor (Dashboard → SQL Editor → New Query)
--
-- PROBLEM
-- Changing the dashboard date range was slow and produced WRONG numbers.
-- getOverviewStats fell off its cached fast path whenever a range was set and
-- pulled raw event rows to count them in JavaScript. PostgREST caps a response
-- at a fixed row limit well below the requested one, so the overview for a
-- filtered range was computed from only a small sample of the matching events.
--
-- FIX
-- 1. Composite indexes so a (run_id + event_time) range scan is an index scan.
--    The rpc.sql comments already referenced idx_events_run_source and
--    idx_events_run_phase, but neither was ever created.
-- 2. get_overview_stats: all counting happens in Postgres, one round trip,
--    no row cap, exact numbers.
-- 3. get_run_counts: replaces the N+1 exact-count queries the run dropdown
--    issued on every page load (two per run) with a single grouped pass.

-- ---------------------------------------------------------------------------
-- 1. Indexes
-- ---------------------------------------------------------------------------
-- Range filtering and ordering within a run.
create index if not exists idx_events_run_time
  on events (run_id, event_time);

-- Grouped counts by source within a run and range (supports index-only scan).
create index if not exists idx_events_run_source
  on events (run_id, source, event_time);

-- Grouped counts by phase. Partial: unclassified events are never aggregated,
-- which keeps the index small on runs where most events carry no phase.
create index if not exists idx_events_run_phase
  on events (run_id, kill_chain_phase, event_time)
  where kill_chain_phase is not null;

-- Covering index for the overview aggregation. INCLUDE carries source and
-- kill_chain_phase in the index leaf, so counting a date range never touches
-- the heap — an index-only scan. This matters because the capture is bursty:
-- most events fall within a small number of days, so a range query routinely
-- aggregates a large share of the run in one go.
create index if not exists idx_events_run_time_cover
  on events (run_id, event_time) include (source, kill_chain_phase);

-- Incident range filtering within a run.
create index if not exists idx_incidents_run_seen
  on incidents (run_id, first_seen, last_seen);

-- Let the planner see the new indexes immediately.
analyze events;
analyze incidents;

-- ---------------------------------------------------------------------------
-- 2. Drop any existing versions of the functions we are about to define.
--
-- `create or replace` cannot change a function's return type, and an older
-- get_overview_stats already exists in some databases with a different return
-- shape. Dropping by name covers every overload regardless of its signature.
-- Neither function is referenced anywhere except the dashboard code shipped
-- alongside this migration, so replacing them is safe.
-- ---------------------------------------------------------------------------
do $$
declare
  fn record;
begin
  for fn in
    select p.oid::regprocedure as sig
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname in ('get_overview_stats', 'get_run_counts')
  loop
    execute format('drop function if exists %s', fn.sig);
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 3. Overview stats in a single call
-- ---------------------------------------------------------------------------
create function get_overview_stats(
  p_run_id  uuid,
  from_date timestamptz default null,
  to_date   timestamptz default null
)
returns json
language sql
stable
as $$
  -- One pass over events, grouped by (source, phase). That grouping collapses
  -- the scanned rows into at most a couple of dozen, and all four outputs are
  -- then derived from that tiny result. The earlier version ran a separate
  -- scan for each output, which exceeded the statement timeout on wide ranges.
  with g as (
    select source, kill_chain_phase as phase, count(*) as cnt
    from events
    where run_id = p_run_id
      -- coalesce, NOT `(param is null or col >= param)`. The OR form is not
      -- sargable: the planner cannot use an index for it and falls back to a
      -- sequential scan of a table carrying a wide jsonb column, which is slow
      -- even for a one-hour range. Collapsing the bounds to constants keeps
      -- this an index range scan, and INCLUDE makes it index-only.
      and event_time >= coalesce(from_date, '-infinity'::timestamptz)
      and event_time <= coalesce(to_date,    'infinity'::timestamptz)
    group by source, kill_chain_phase
  )
  select json_build_object(
    'total',      (select coalesce(sum(cnt), 0) from g),
    'classified', (select coalesce(sum(cnt), 0) from g where phase is not null),
    'by_source',  coalesce(
      (select json_object_agg(source, total)
       from (select source, sum(cnt) as total
             from g where source is not null
             group by source) s),
      '{}'::json),
    'by_phase',   coalesce(
      (select json_object_agg(phase, total)
       from (select phase, sum(cnt) as total
             from g where phase is not null
             group by phase) p),
      '{}'::json)
  )
$$;

-- ---------------------------------------------------------------------------
-- 4. Run dropdown counts without N+1
-- ---------------------------------------------------------------------------
create function get_run_counts()
returns table(run_id uuid, event_count bigint, incident_count bigint)
language sql
stable
as $$
  select r.id,
         coalesce(e.cnt, 0),
         coalesce(i.cnt, 0)
  from correlation_runs r
  left join (select run_id, count(*) as cnt from events    group by run_id) e on e.run_id = r.id
  left join (select run_id, count(*) as cnt from incidents group by run_id) i on i.run_id = r.id
$$;


-- ---------------------------------------------------------------------------
-- 5. Repair the same defect in the original per-source / per-phase RPCs.
--
-- Both were written with `(param is null or col >= param)`, so neither could
-- use an index and both scanned the whole events table on every call. They are
-- redefined here with sargable bounds. Signatures are unchanged, so any
-- existing caller keeps working.
-- ---------------------------------------------------------------------------
create or replace function get_event_counts_by_source(
  p_run_id  uuid,
  from_date timestamptz default null,
  to_date   timestamptz default null
)
returns table(source text, cnt bigint)
language sql
stable
as $$
  select source, count(*) as cnt
  from events
  where run_id = p_run_id
    and event_time >= coalesce(from_date, '-infinity'::timestamptz)
    and event_time <= coalesce(to_date,    'infinity'::timestamptz)
  group by source
$$;

create or replace function get_event_counts_by_phase(
  p_run_id  uuid,
  from_date timestamptz default null,
  to_date   timestamptz default null
)
returns table(phase text, cnt bigint)
language sql
stable
as $$
  select kill_chain_phase as phase, count(*) as cnt
  from events
  where run_id = p_run_id
    and kill_chain_phase is not null
    and event_time >= coalesce(from_date, '-infinity'::timestamptz)
    and event_time <= coalesce(to_date,    'infinity'::timestamptz)
  group by kill_chain_phase
$$;
