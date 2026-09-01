-- Add incident status workflow
-- Run this in Supabase SQL Editor

create type incident_status_t as enum ('new', 'investigating', 'resolved');

alter table incidents
  add column status incident_status_t not null default 'new',
  add column status_changed_at timestamptz,
  add column status_changed_by text;

create index idx_incidents_status on incidents (status);
