-- Removes the incident activity summary (the dashboard card was dropped).
-- Optional: nothing reads these any more.
drop function if exists get_incident_activity(uuid);
alter table incidents drop column if exists activity;
