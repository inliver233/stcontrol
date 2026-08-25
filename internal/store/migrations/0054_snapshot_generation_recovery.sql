-- 0054: Controller restarts may safely retry a snapshot without consuming its
-- ordinary transport retry budget. The total attempt still changes so every
-- generation receives fresh command and relay operation identities.
ALTER TABLE workflows
  ADD COLUMN IF NOT EXISTS generation_recovery_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE workflows
  DROP CONSTRAINT IF EXISTS workflows_generation_recovery_count_check;

ALTER TABLE workflows
  ADD CONSTRAINT workflows_generation_recovery_count_check CHECK (
    generation_recovery_count >= 0 AND generation_recovery_count <= attempt
  );
