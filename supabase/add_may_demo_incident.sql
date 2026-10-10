-- GCTU-SIEM Correlation Engine — 1–7 May incident on the Legacy run (demo)
-- Run in your Supabase SQL Editor (Dashboard → SQL Editor → New Query)
--
-- PURPOSE
-- The Legacy incident spans 5 May → 19 Aug, so the dashboard's 1–7 May filter
-- (which shows incidents lying wholly inside the window) hides it. This adds a
-- second incident to the Legacy run covering only the simulation period stated
-- in the thesis, 1–7 May 2026. Nothing existing is modified.
--
-- It is built from the Legacy incident's own evidence links dated 1–7 May:
--   reconnaissance 200,763 · command_and_control 158 · delivery 62 ·
--   exploitation 15 · persistence 1  =  200,999 events, 5 May 20:27 → 7 May 14:00
-- These are identical to a fresh engine run over 1–7 May (dry-run checked),
-- and score 96 by the score.ts formula: 5/5 phases × 50 + 3 milestones × 15
-- + velocity 1 (campaign longer than 24 h).
--
-- The new incident is SCOPED to 1–7 May (scope_from / scope_to). The dashboard
-- shows a scoped incident only when the selected date range sits inside its
-- window, so: "All" shows only the original incident, 1–7 May shows only this
-- one. Evaluation and the run dropdown count ignore scoped incidents.
--
-- HOW TO RUN
--   Step 0 — run once, FIRST: the updated dashboard code filters on these
--            columns and its incident queries fail until they exist.
--   Step 1 — run once.
--   Step 2 — run `select add_may_demo_links();` until it says done.
--   Step 3 — undo, if ever wanted (commented out).

-- ---------------------------------------------------------------------------
-- STEP 0 — scope columns + run counts that ignore scoped incidents
-- ---------------------------------------------------------------------------
-- Null on every existing incident, so existing incidents behave as before.
alter table incidents
  add column if not exists scope_from timestamptz,
  add column if not exists scope_to   timestamptz;

-- Same as add_dashboard_perf.sql, but a scoped incident re-presents an engine
-- incident over a sub-window, so it is not counted as another incident.
create or replace function get_run_counts()
returns table(run_id uuid, event_count bigint, incident_count bigint)
language sql
stable
as $$
  select r.id,
         coalesce(e.cnt, 0),
         coalesce(i.cnt, 0)
  from correlation_runs r
  left join (select run_id, count(*) as cnt from events    group by run_id) e on e.run_id = r.id
  left join (select run_id, count(*) as cnt from incidents
             where scope_from is null group by run_id) i on i.run_id = r.id
$$;

-- ---------------------------------------------------------------------------
-- STEP 1 — the incident (run once; safe to re-run)
-- ---------------------------------------------------------------------------
insert into incidents (
  id, run_id, attacker_ip, victim_ip, first_seen, last_seen,
  phases_detected, phase_count, risk_score, severity, event_count, summary,
  scope_from, scope_to
)
select
  'a0000000-0000-0000-0000-000000000507',
  o.run_id, o.attacker_ip, o.victim_ip,
  w.first_seen, w.last_seen,
  w.phases, cardinality(w.phases),
  s.score,
  (case when s.score >= 80 then 'critical'
        when s.score >= 60 then 'high'
        when s.score >= 40 then 'medium'
        else 'low' end)::severity_t,
  w.n,
  o.summary,
  '2026-05-01T00:00:00Z', '2026-05-07T23:59:59.999Z'
from incidents o
cross join lateral (
  select count(*)            as n,
         min(e.event_time)   as first_seen,
         max(e.event_time)   as last_seen,
         array(select p from unnest(array['reconnaissance','delivery','exploitation',
                                          'persistence','command_and_control']) p
               where p = any (array_agg(distinct ie.phase))) as phases
  from incident_events ie
  join events e on e.id = ie.event_id
  where ie.incident_id = o.id
    and e.event_time >= '2026-05-01T00:00:00Z'
    and e.event_time <  '2026-05-08T00:00:00Z'
) w
cross join lateral (
  select round(least(100, greatest(0,
           cardinality(w.phases) / 5.0 * 50
           + 15 * (('exploitation'        = any (w.phases))::int)
           + 15 * (('persistence'         = any (w.phases))::int)
           + 15 * (('command_and_control' = any (w.phases))::int)
           + case when w.last_seen - w.first_seen <= interval '1 hour'   then 10
                  when w.last_seen - w.first_seen <= interval '6 hours'  then 7
                  when w.last_seen - w.first_seen <= interval '24 hours' then 4
                  else 1 end)))::int as score
) s
where o.id = '350d27ed-c3fb-46d9-8e09-b1c73885d7c1'
on conflict (id) do nothing;

-- Check: expect 200999 events, 5 phases, score 96, critical,
-- 2026-05-05 20:27:04 → 2026-05-07 14:00:00.
select first_seen, last_seen, phases_detected, phase_count, risk_score,
       severity, event_count, scope_from, scope_to
from incidents
where id = 'a0000000-0000-0000-0000-000000000507';

-- ---------------------------------------------------------------------------
-- STEP 2 — evidence links for the detail view, in batches
-- ---------------------------------------------------------------------------
-- Copies the Legacy incident's 1–7 May links to the new incident. Each call
-- adds up to `batch` links not yet copied, so re-running is always safe.
create or replace function add_may_demo_links(batch int default 50000) returns text
language plpgsql as $$
declare
  added  int;
  total  bigint;
begin
  insert into incident_events (incident_id, event_id, phase)
  select 'a0000000-0000-0000-0000-000000000507', ie.event_id, ie.phase
  from incident_events ie
  join events e on e.id = ie.event_id
  where ie.incident_id = '350d27ed-c3fb-46d9-8e09-b1c73885d7c1'
    and e.event_time >= '2026-05-01T00:00:00Z'
    and e.event_time <  '2026-05-08T00:00:00Z'
    and not exists (
      select 1 from incident_events x
      where x.incident_id = 'a0000000-0000-0000-0000-000000000507'
        and x.event_id = ie.event_id)
  limit batch;
  get diagnostics added = row_count;

  select count(*) into total from incident_events
  where incident_id = 'a0000000-0000-0000-0000-000000000507';
  return format('Added %s links — %s of 200999 copied%s', added, total,
                case when added = 0 then ' — done.' else ' — run it again.' end);
end $$;

revoke execute on function add_may_demo_links(int) from public, anon, authenticated;

select add_may_demo_links();

-- When it reports done, the helper can go:
-- drop function add_may_demo_links(int);

-- ---------------------------------------------------------------------------
-- STEP 3 — UNDO: removes the demo incident and its links (cascade)
-- ---------------------------------------------------------------------------
-- delete from incidents where id = 'a0000000-0000-0000-0000-000000000507';
