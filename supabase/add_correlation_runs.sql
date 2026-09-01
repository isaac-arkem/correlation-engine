-- GCTU-SIEM Correlation Engine — Correlation Runs
-- Run this in your Supabase SQL Editor (Dashboard → SQL Editor → New Query)
-- This adds dataset isolation: each correlation run is tagged so results never mix.

-- 1. New table for tracking correlation runs
CREATE TABLE correlation_runs (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  label          text NOT NULL,
  source_type    text NOT NULL DEFAULT 'file',
  attacker_ips   text[] NOT NULL,
  victim_ips     text[] NOT NULL,
  c2_ports       int[] NOT NULL,
  event_count    int NOT NULL DEFAULT 0,
  incident_count int NOT NULL DEFAULT 0,
  status         text NOT NULL DEFAULT 'running',
  error          text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  completed_at   timestamptz
);

CREATE INDEX idx_runs_created ON correlation_runs (created_at DESC);

-- 2. Add run_id foreign key to events and incidents
ALTER TABLE events    ADD COLUMN run_id uuid REFERENCES correlation_runs(id) ON DELETE CASCADE;
ALTER TABLE incidents ADD COLUMN run_id uuid REFERENCES correlation_runs(id) ON DELETE CASCADE;

CREATE INDEX idx_events_run    ON events(run_id);
CREATE INDEX idx_incidents_run ON incidents(run_id);

-- 3. Backfill: create a legacy run for any existing data
INSERT INTO correlation_runs (id, label, source_type, attacker_ips, victim_ips, c2_ports, status, completed_at)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  'Legacy — Initial Experiment',
  'file',
  ARRAY['192.168.64.2'],
  ARRAY['192.168.64.3'],
  ARRAY[4444, 5555],
  'completed',
  now()
);

UPDATE events    SET run_id = '00000000-0000-0000-0000-000000000001' WHERE run_id IS NULL;
UPDATE incidents SET run_id = '00000000-0000-0000-0000-000000000001' WHERE run_id IS NULL;

-- Update the legacy run counts to match existing data
UPDATE correlation_runs
SET event_count    = (SELECT count(*) FROM events    WHERE run_id = '00000000-0000-0000-0000-000000000001'),
    incident_count = (SELECT count(*) FROM incidents WHERE run_id = '00000000-0000-0000-0000-000000000001')
WHERE id = '00000000-0000-0000-0000-000000000001';

-- 4. Make run_id NOT NULL after backfill
ALTER TABLE events    ALTER COLUMN run_id SET NOT NULL;
ALTER TABLE incidents ALTER COLUMN run_id SET NOT NULL;

-- 5. RLS
ALTER TABLE correlation_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read runs"
  ON correlation_runs FOR SELECT TO authenticated USING (true);
