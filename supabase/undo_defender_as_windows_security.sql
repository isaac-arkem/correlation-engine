-- Undo a run of add_defender_persistence_events.sql that was edited to use
-- source 'windows_security'. That version linked EVERY windows_security event
-- in the Legacy run (the 372 August Security events + the 9 Defender rows) to
-- the 1–7 May incident as persistence: 1 + 381 = 382.
--
-- Run step 1 first and check the numbers before step 2.

-- STEP 1 — check (read-only). Expect: 9 rows inserted, 381 wrong links.
select
  (select count(*) from events where id in (
     '9951ec4c-23d3-5ca7-ba88-1a86a0380e6e','13ab0d84-2eb3-5cd4-9f22-fbe7ce5d74c5',
     'e5fa2646-f2bf-5623-9a4e-415a359dfd65','09560dd5-8a29-5d05-bad7-73c06facfe41',
     '9285954d-0c1d-5a31-918c-172e8c7df8a1','648576fd-ff9a-5453-a45f-c5fb73700f0d',
     '9fe835c8-761c-5fd3-bffa-600eb5daa866','356e13ef-ed13-5b09-800a-de3789a3e57f',
     '20efb4f5-f51b-577b-8daa-8d78faf3e061')) as inserted_rows,
  (select count(*) from incident_events ie join events e on e.id = ie.event_id
    where ie.incident_id = 'a0000000-0000-0000-0000-000000000507'
      and e.source = 'windows_security') as wrong_may_links,
  (select source_counts from correlation_runs
    where id = '00000000-0000-0000-0000-000000000001') as run_source_counts,
  (select phase_counts from correlation_runs
    where id = '00000000-0000-0000-0000-000000000001') as run_phase_counts;

-- STEP 2 — undo, all or nothing
begin;

-- The May incident's Windows Security links (none existed before: May has no
-- Security data).
delete from incident_events ie
using events e
where e.id = ie.event_id
  and ie.incident_id = 'a0000000-0000-0000-0000-000000000507'
  and e.source = 'windows_security';

-- The 9 inserted rows; their links to the Legacy incident cascade.
delete from events where id in (
  '9951ec4c-23d3-5ca7-ba88-1a86a0380e6e','13ab0d84-2eb3-5cd4-9f22-fbe7ce5d74c5',
  'e5fa2646-f2bf-5623-9a4e-415a359dfd65','09560dd5-8a29-5d05-bad7-73c06facfe41',
  '9285954d-0c1d-5a31-918c-172e8c7df8a1','648576fd-ff9a-5453-a45f-c5fb73700f0d',
  '9fe835c8-761c-5fd3-bffa-600eb5daa866','356e13ef-ed13-5b09-800a-de3789a3e57f',
  '20efb4f5-f51b-577b-8daa-8d78faf3e061');

-- Cached totals back by the 9 that the edited run added.
update incidents set event_count = event_count - 9
where id in ('350d27ed-c3fb-46d9-8e09-b1c73885d7c1', 'a0000000-0000-0000-0000-000000000507');

update correlation_runs
set event_count   = event_count - 9,
    source_counts = source_counts || jsonb_build_object('windows_security',
                      (source_counts->>'windows_security')::int - 9),
    phase_counts  = phase_counts || jsonb_build_object('persistence',
                      (phase_counts->>'persistence')::int - 9)
where id = '00000000-0000-0000-0000-000000000001';

-- Expect 372 windows_security and 0 May persistence links from that source.
select (select count(*) from events
         where run_id = '00000000-0000-0000-0000-000000000001'
           and source = 'windows_security') as windows_security_events,
       (select count(*) from incident_events ie join events e on e.id = ie.event_id
         where ie.incident_id = 'a0000000-0000-0000-0000-000000000507'
           and e.source = 'windows_security') as may_links_left;

commit;
