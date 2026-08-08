ALTER TABLE nodes DROP CONSTRAINT IF EXISTS nodes_operational_state_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_operational_state_check
  CHECK (operational_state IN (
    'pending','active','maintenance','draining','retiring',
    'degraded','failed','decommissioned','retired'
  ));

CREATE TABLE IF NOT EXISTS node_retirement_operations (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operation_id          UUID NOT NULL UNIQUE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  requested_by_admin_id BIGINT REFERENCES admins(id) ON DELETE SET NULL,
  reason_code           TEXT NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  state                 TEXT NOT NULL CHECK (state IN (
                          'scheduled','migrating','retry_wait','verifying',
                          'blocked','decommissioned','cancelled','failed')),
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  lease_owner           UUID,
  lease_until           TIMESTAMPTZ,
  next_attempt_at       TIMESTAMPTZ,
  attempt               INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  error_code            TEXT,
  created_at            TIMESTAMPTZ NOT NULL,
  updated_at            TIMESTAMPTZ NOT NULL,
  completed_at          TIMESTAMPTZ,
  CHECK ((state='decommissioned')=(completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_node_retirement_one_open
  ON node_retirement_operations (node_id)
  WHERE state NOT IN ('decommissioned','cancelled','failed');
CREATE INDEX IF NOT EXISTS idx_node_retirement_schedulable
  ON node_retirement_operations (state,next_attempt_at,updated_at)
  WHERE state IN ('scheduled','migrating','retry_wait','verifying','blocked');

CREATE TABLE IF NOT EXISTS node_retirement_items (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  retirement_id         UUID NOT NULL REFERENCES node_retirement_operations(id) ON DELETE CASCADE,
  user_id               BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  legacy_user_id        BIGINT REFERENCES users(id) ON DELETE SET NULL,
  source_node_id        BIGINT NOT NULL REFERENCES nodes(id),
  target_node_id        BIGINT REFERENCES nodes(id),
  item_kind             TEXT NOT NULL CHECK (item_kind IN (
                          'authoritative_home','archive_replica',
                          'redundant_replica','account_metadata')),
  state                 TEXT NOT NULL CHECK (state IN (
                          'pending','waiting_offline','provisioning','snapshotting',
                          'promoting','verifying','retry_wait','blocked','failed',
                          'succeeded','superseded')),
  workflow_id           UUID UNIQUE REFERENCES workflows(id) ON DELETE SET NULL,
  attempt               INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  next_attempt_at       TIMESTAMPTZ,
  error_code            TEXT,
  created_at            TIMESTAMPTZ NOT NULL,
  updated_at            TIMESTAMPTZ NOT NULL,
  completed_at          TIMESTAMPTZ,
  UNIQUE (retirement_id,user_id),
  CHECK ((state IN ('succeeded','superseded'))=(completed_at IS NOT NULL)),
  CHECK (target_node_id IS NULL OR target_node_id<>source_node_id)
);
CREATE INDEX IF NOT EXISTS idx_node_retirement_items_work
  ON node_retirement_items (retirement_id,state,next_attempt_at,updated_at);
CREATE INDEX IF NOT EXISTS idx_node_retirement_items_user
  ON node_retirement_items (user_id,state);
