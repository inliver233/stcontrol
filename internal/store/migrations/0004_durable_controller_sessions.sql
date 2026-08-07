ALTER TABLE controller_sessions ADD COLUMN IF NOT EXISTS controller_generation BIGINT;
UPDATE controller_sessions
SET controller_generation = (
  SELECT generation FROM controller_epochs WHERE state='active' LIMIT 1
)
WHERE controller_generation IS NULL;
ALTER TABLE controller_sessions ALTER COLUMN controller_generation SET NOT NULL;
ALTER TABLE controller_sessions
  ADD CONSTRAINT fk_controller_sessions_generation
  FOREIGN KEY (controller_generation) REFERENCES controller_epochs(generation) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_controller_sessions_expiry
  ON controller_sessions (expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_controller_sessions_user
  ON controller_sessions (user_id) WHERE revoked_at IS NULL;
