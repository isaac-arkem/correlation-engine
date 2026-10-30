-- Attach the AIT Log Data Set V1.1 declared ground truth to the
-- "evaluation-on-real-public-data" correlation run.
--
-- Source of truth: AIT's own published attack log (attack 1, 2020-03-04):
--   attacker  user-5 host  192.168.10.81
--   victim    mail.spiral.com 192.168.10.122
--   phases    reconnaissance (nmap/nikto/vrfy/hydra) -> delivery (Horde webshell upload)
--
-- With this declared answer key present, the Evaluation page switches from
-- "Derived" (circular, self-counting) to "Declared ground truth" mode and
-- computes detection accuracy against external truth:
--   TP = 1  (192.168.10.81 reconstructed)
--   FP = 2  (192.168.10.130 and .194 are benign hosts -> "Extra incident")
--   FN = 0  (the one declared campaign was found)
--   => Precision 33.3%  Recall 100%  F1 50%
--
-- Run in the Supabase SQL editor. Re-runnable (overwrites the column).

update correlation_runs
set ground_truth = jsonb_build_object(
  'label', 'AIT Log Data Set V1.1 — published attack log',
  'campaigns', jsonb_build_array(
    jsonb_build_object(
      'attackerIp',     '192.168.10.81',
      'victimIp',       '192.168.10.122',
      'expectedPhases', jsonb_build_array('reconnaissance','delivery'),
      'note',           'AIT Attack 1: user-5 nmap/nikto scan + Horde webshell upload, 2020-03-04'
    )
  )
)
where label = 'evaluation-on-real-public-data';

-- Verify (optional):
-- select label, ground_truth from correlation_runs where label = 'evaluation-on-real-public-data';
