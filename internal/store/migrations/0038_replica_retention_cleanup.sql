-- R09: retain exactly one successful archive and durably clean superseded
-- archive/temporary-compute replicas without letting delayed work delete a
-- replacement published at the same path.
ALTER TABLE replica_copies DROP CONSTRAINT IF EXISTS replica_copies_origin_check;
ALTER TABLE replica_copies ADD CONSTRAINT replica_copies_origin_check CHECK (
  origin IN ('primary','configured','temporary_failure_protection','migration','recovery','automatic_repair')
);

WITH ranked AS (
  SELECT copy.user_id,copy.node_id,row_number() OVER (
    PARTITION BY copy.user_id
    ORDER BY copy.published_at DESC NULLS LAST,copy.updated_at DESC,copy.id
  ) AS ready_rank
  FROM replica_copies copy
  WHERE copy.replica_kind='archive' AND copy.state='ready'
), duplicates AS (
  SELECT global_user.legacy_user_id,ranked.node_id
  FROM ranked
  JOIN global_users global_user ON global_user.id=ranked.user_id
  WHERE ranked.ready_rank>1
)
UPDATE user_replicas replica SET state='stale'
FROM duplicates
WHERE replica.user_id=duplicates.legacy_user_id
  AND replica.node_id=duplicates.node_id
  AND replica.kind='archive' AND replica.state='ready';

WITH ranked AS (
  SELECT id,row_number() OVER (
    PARTITION BY user_id ORDER BY published_at DESC NULLS LAST,updated_at DESC,id
  ) AS ready_rank
  FROM replica_copies
  WHERE replica_kind='archive' AND state='ready'
)
UPDATE replica_copies copy SET state='stale',updated_at=now()
FROM ranked WHERE copy.id=ranked.id AND ranked.ready_rank>1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_replica_one_ready_archive
  ON replica_copies (user_id)
  WHERE replica_kind='archive' AND state='ready';

CREATE TABLE IF NOT EXISTS replica_cleanup_tasks (
  id                    UUID PRIMARY KEY,
  replica_id            UUID NOT NULL,
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  legacy_user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  snapshot_id           UUID NOT NULL REFERENCES snapshot_manifests(id) ON DELETE RESTRICT,
  handle                TEXT NOT NULL,
  replica_kind          TEXT NOT NULL CHECK (replica_kind IN ('archive','hot_standby')),
  reason_code           TEXT NOT NULL CHECK (reason_code IN ('superseded_archive','stable_archive_available')),
  state                 TEXT NOT NULL DEFAULT 'pending'
                          CHECK (state IN ('pending','running','retry_wait','succeeded','cancelled','failed')),
  attempt               INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  next_attempt_at       TIMESTAMPTZ NOT NULL,
  operation_id          UUID,
  controller_generation BIGINT,
  lease_owner           TEXT,
  lease_until           TIMESTAMPTZ,
  error_code            TEXT,
  agent_outcome         TEXT CHECK (agent_outcome IS NULL OR agent_outcome IN (
                          'deleted','already_absent','superseded')),
  created_at            TIMESTAMPTZ NOT NULL,
  updated_at            TIMESTAMPTZ NOT NULL,
  finished_at           TIMESTAMPTZ,
  UNIQUE (node_id,snapshot_id,replica_kind)
);

CREATE INDEX IF NOT EXISTS idx_replica_cleanup_due
  ON replica_cleanup_tasks (next_attempt_at,created_at,id)
  WHERE state IN ('pending','retry_wait','running');
