-- Failure recovery for legacy replica cleanup (R09): FailReplicaCleanupTask
-- returns an unverifiable legacy replica to ready/stale. The transition needs
-- a durable updated_at on user_replicas so operators can see when the state
-- was last touched; before this migration the column did not exist and the
-- recovery UPDATE failed on real PostgreSQL.
ALTER TABLE user_replicas
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
