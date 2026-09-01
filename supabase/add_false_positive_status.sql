-- Add false_positive to the incident status enum
-- Run this in Supabase SQL Editor

ALTER TYPE incident_status_t ADD VALUE IF NOT EXISTS 'false_positive';
