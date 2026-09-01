-- GCTU-SIEM Correlation Engine — RPC Functions
-- Run this in your Supabase SQL Editor (Dashboard → SQL Editor → New Query)

-- Index on source for fast aggregation (run once)
create index if not exists idx_events_source on events (source);

-- 1a. Event counts grouped by source (dynamic — works with any source type)
--     Uses idx_events_run_source composite index for fast grouped counts.
create or replace function get_event_counts_by_source(
  p_run_id  uuid,
  from_date timestamptz default null,
  to_date   timestamptz default null
)
returns table(source text, cnt bigint)
language sql stable
as $$
  select source, count(*) as cnt
  from events
  where run_id = p_run_id
    and (from_date is null or event_time >= from_date)
    and (to_date   is null or event_time <= to_date)
  group by source
$$;

-- 1b. Event counts grouped by kill chain phase (dynamic — works with any phase)
--     Uses idx_events_run_phase composite index for fast grouped counts.
create or replace function get_event_counts_by_phase(
  p_run_id  uuid,
  from_date timestamptz default null,
  to_date   timestamptz default null
)
returns table(phase text, cnt bigint)
language sql stable
as $$
  select kill_chain_phase as phase, count(*) as cnt
  from events
  where run_id = p_run_id
    and kill_chain_phase is not null
    and (from_date is null or event_time >= from_date)
    and (to_date   is null or event_time <= to_date)
  group by kill_chain_phase
$$;

-- 2. Fetch a representative sample of events for an incident (timeline + table)
--    Returns up to max_non_recon attack-phase events + max_recon recon events,
--    joined through the incident_events junction table.
create or replace function get_incident_events(
  p_incident_id   uuid,
  max_non_recon    int default 500,
  max_recon        int default 50
)
returns setof events
language sql stable
as $$
  (
    select e.*
    from incident_events ie
    join events e on e.id = ie.event_id
    where ie.incident_id = p_incident_id
      and ie.phase in ('delivery', 'exploitation', 'persistence', 'command_and_control')
    order by e.event_time
    limit max_non_recon
  )
  union all
  (
    select e.*
    from incident_events ie
    join events e on e.id = ie.event_id
    where ie.incident_id = p_incident_id
      and ie.phase = 'reconnaissance'
    order by e.event_time
    limit max_recon
  )
  order by event_time
$$;

-- 3. Incident phase breakdown — counts from the junction table
create or replace function get_incident_phase_breakdown(p_incident_id uuid)
returns json
language sql stable
as $$
  select coalesce(
    json_object_agg(phase, cnt),
    '{}'::json
  )
  from (
    select phase, count(*) as cnt
    from incident_events
    where incident_id = p_incident_id
      and phase is not null
    group by phase
  ) p
$$;
