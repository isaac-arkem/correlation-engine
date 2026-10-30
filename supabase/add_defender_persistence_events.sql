-- GCTU-SIEM Correlation Engine — Windows Defender persistence detections (Legacy run)
-- Run in your Supabase SQL Editor.
--
-- Adds the 9 Windows Defender detections of the Startup-folder WindowsUpdate.exe
-- (6 May 2026, 15:49:40-15:49:55 and 22:54:27-22:54:39 UTC), recovered from the
-- Windows-target VM's Defender Operational log, as source 'windows_defender',
-- phase 'persistence', linked to the Legacy incident and its 1-7 May incident.
-- Fixed ids make every step safe to re-run.
--
-- RUN STEP 1 ON ITS OWN FIRST: Postgres cannot use a new enum value in the
-- same transaction that adds it.

-- ---------------------------------------------------------------------------
-- STEP 1 — the new source value (run alone)
-- ---------------------------------------------------------------------------
alter type source_t add value if not exists 'windows_defender';

-- ---------------------------------------------------------------------------
-- STEP 2 — events, incident links and cached totals (run after step 1)
-- ---------------------------------------------------------------------------
do $$
declare
  added int;
begin
  insert into events (id, run_id, source, event_time, event_type, event_id,
                      signature, category, message, kill_chain_phase)
  select v.id::uuid, '00000000-0000-0000-0000-000000000001', 'windows_defender',
         v.t::timestamptz, 'defender_detection', v.eid, v.sig, 'Trojan', v.msg,
         'persistence'
  from (values
  ('9951ec4c-23d3-5ca7-ba88-1a86a0380e6e', '2026-05-06T15:49:40.335165+00:00', 1116, 'Trojan:Win32/Zusy.NCD!MTB', 'Windows Defender 1116 (malware detected): Trojan:Win32/Zusy.NCD!MTB in C:\Users\isaac\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe - action: Not Applicable'),
  ('13ab0d84-2eb3-5cd4-9f22-fbe7ce5d74c5', '2026-05-06T15:49:50.353245+00:00', 1116, 'Trojan:Win32/Zusy.NCD!MTB', 'Windows Defender 1116 (malware detected): Trojan:Win32/Zusy.NCD!MTB in C:\Users\isaac\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe - action: Not Applicable'),
  ('e5fa2646-f2bf-5623-9a4e-415a359dfd65', '2026-05-06T15:49:52.113771+00:00', 1116, 'Trojan:Win32/Zusy.NCD!MTB', 'Windows Defender 1116 (malware detected): Trojan:Win32/Zusy.NCD!MTB in C:\Users\isaac\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe - action: Not Applicable'),
  ('09560dd5-8a29-5d05-bad7-73c06facfe41', '2026-05-06T15:49:52.333651+00:00', 1117, 'Trojan:Win32/Zusy.NCD!MTB', 'Windows Defender 1117 (action taken): Trojan:Win32/Zusy.NCD!MTB in C:\Users\isaac\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe - action: Quarantine'),
  ('9285954d-0c1d-5a31-918c-172e8c7df8a1', '2026-05-06T15:49:52.338736+00:00', 1116, 'Trojan:Win32/Zusy.NCD!MTB', 'Windows Defender 1116 (malware detected): Trojan:Win32/Zusy.NCD!MTB in C:\Users\isaac\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe - action: Not Applicable'),
  ('648576fd-ff9a-5453-a45f-c5fb73700f0d', '2026-05-06T15:49:55.111992+00:00', 1117, 'Trojan:Win32/Zusy.NCD!MTB', 'Windows Defender 1117 (action taken): Trojan:Win32/Zusy.NCD!MTB in C:\Users\isaac\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe - action: Quarantine'),
  ('9fe835c8-761c-5fd3-bffa-600eb5daa866', '2026-05-06T22:54:27.808170+00:00', 1116, 'Trojan:Win32/Zusy.NCD!MTB', 'Windows Defender 1116 (malware detected): Trojan:Win32/Zusy.NCD!MTB in C:\Users\isaac\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe - action: Not Applicable'),
  ('356e13ef-ed13-5b09-800a-de3789a3e57f', '2026-05-06T22:54:38.994999+00:00', 1116, 'Trojan:Win32/Zusy.NCD!MTB', 'Windows Defender 1116 (malware detected): Trojan:Win32/Zusy.NCD!MTB in C:\Users\isaac\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe - action: Not Applicable'),
  ('20efb4f5-f51b-577b-8daa-8d78faf3e061', '2026-05-06T22:54:39.297930+00:00', 1117, 'Trojan:Win32/Zusy.NCD!MTB', 'Windows Defender 1117 (action taken): Trojan:Win32/Zusy.NCD!MTB in C:\Users\isaac\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe - action: Quarantine')
  ) as v(id, t, eid, sig, msg)
  on conflict (id) do nothing;
  get diagnostics added = row_count;

  -- Link to the Legacy incident and to the 1-7 May incident.
  insert into incident_events (incident_id, event_id, phase)
  select i.id, e.id, 'persistence'
  from events e
  cross join (values ('350d27ed-c3fb-46d9-8e09-b1c73885d7c1'::uuid),
                     ('a0000000-0000-0000-0000-000000000507'::uuid)) as i(id)
  where e.run_id = '00000000-0000-0000-0000-000000000001'
    and e.source = 'windows_defender'
    and exists (select 1 from incidents x where x.id = i.id)
  on conflict do nothing;

  -- Cached totals, only for rows this run actually added.
  if added > 0 then
    update incidents set event_count = event_count + added
    where id in ('350d27ed-c3fb-46d9-8e09-b1c73885d7c1', 'a0000000-0000-0000-0000-000000000507');

    update correlation_runs
    set event_count   = event_count + added,
        source_counts = coalesce(source_counts, '{}'::jsonb)
                        || jsonb_build_object('windows_defender',
                             coalesce((source_counts->>'windows_defender')::int, 0) + added),
        phase_counts  = coalesce(phase_counts, '{}'::jsonb)
                        || jsonb_build_object('persistence',
                             coalesce((phase_counts->>'persistence')::int, 0) + added)
    where id = '00000000-0000-0000-0000-000000000001';
  end if;

  raise notice 'Added % Defender events', added;
end $$;

-- Check: expect 9 rows, and 9 links per incident.
select e.event_time, e.event_id, e.signature, e.kill_chain_phase,
       (select count(*) from incident_events ie where ie.event_id = e.id) as incident_links
from events e
where e.run_id = '00000000-0000-0000-0000-000000000001' and e.source = 'windows_defender'
order by e.event_time;

-- ---------------------------------------------------------------------------
-- UNDO (commented out): removes the 9 events (links cascade) and the counts
-- ---------------------------------------------------------------------------
-- update incidents set event_count = event_count - 9
--   where id in ('350d27ed-c3fb-46d9-8e09-b1c73885d7c1', 'a0000000-0000-0000-0000-000000000507');
-- update correlation_runs
--   set event_count = event_count - 9,
--       source_counts = source_counts - 'windows_defender',
--       phase_counts = jsonb_set(phase_counts, '{persistence}',
--                        to_jsonb((phase_counts->>'persistence')::int - 9))
--   where id = '00000000-0000-0000-0000-000000000001';
-- delete from events
--   where run_id = '00000000-0000-0000-0000-000000000001' and source = 'windows_defender';

