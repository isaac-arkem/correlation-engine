-- GCTU-SIEM Correlation Engine — Supabase Schema
-- Run this in your Supabase SQL Editor (Dashboard → SQL Editor → New Query)

create type source_t   as enum ('suricata','windows_security','powershell');
create type severity_t as enum ('low','medium','high','critical');

create table events (
  id uuid primary key default gen_random_uuid(),
  source source_t not null,
  event_time timestamptz not null,
  event_type text,
  event_id int,
  src_ip text,
  dest_ip text,
  src_port int,
  dest_port int,
  proto text,
  signature text,
  category text,
  message text,
  kill_chain_phase text,
  raw jsonb
);

create index idx_events_time on events (event_time);
create index idx_events_phase on events (kill_chain_phase);
create index idx_events_ips on events (src_ip, dest_ip);

create table incidents (
  id uuid primary key default gen_random_uuid(),
  attacker_ip text,
  victim_ip text,
  first_seen timestamptz,
  last_seen timestamptz,
  phases_detected text[],
  phase_count int,
  risk_score int,
  severity severity_t,
  event_count int,
  summary text,
  created_at timestamptz default now()
);

create index idx_incidents_first on incidents (first_seen);
create index idx_incidents_risk on incidents (risk_score desc);

create table incident_events (
  incident_id uuid references incidents(id) on delete cascade,
  event_id uuid references events(id) on delete cascade,
  phase text,
  primary key (incident_id, event_id)
);

-- RLS: allow authenticated users to read all data
alter table events enable row level security;
alter table incidents enable row level security;
alter table incident_events enable row level security;

create policy "Authenticated users can read events"
  on events for select to authenticated using (true);

create policy "Authenticated users can read incidents"
  on incidents for select to authenticated using (true);

create policy "Authenticated users can read incident_events"
  on incident_events for select to authenticated using (true);
