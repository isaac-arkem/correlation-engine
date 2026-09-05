-- GCTU-SIEM Correlation Engine — Declared Ground Truth
-- Run this in your Supabase SQL Editor (Dashboard → SQL Editor → New Query)
--
-- Stores the expected attack campaigns for a run, declared INDEPENDENTLY of
-- what the engine detected. Evaluation compares emitted incidents against this
-- list instead of re-deriving an answer key from the engine's own output, so
-- precision/recall measure detection accuracy rather than internal consistency.
--
-- Shape:
--   {
--     "label": "Synthetic lab v1",
--     "campaigns": [
--       { "attackerIp": "10.20.30.2", "victimIp": "10.20.40.10",
--         "expectedPhases": ["reconnaissance","delivery","exploitation",
--                            "persistence","command_and_control"],
--         "note": "primary staged campaign" }
--     ]
--   }
--
-- NULL means no ground truth was declared for that run; evaluation then falls
-- back to the derived (circular) method and labels itself as such.

ALTER TABLE correlation_runs ADD COLUMN IF NOT EXISTS ground_truth jsonb;

COMMENT ON COLUMN correlation_runs.ground_truth IS
  'Declared expected campaigns for evaluation. NULL = derived ground truth only.';
