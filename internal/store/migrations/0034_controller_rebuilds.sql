CREATE TABLE IF NOT EXISTS controller_rebuild_operations (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operation_id        UUID NOT NULL UNIQUE,
  generation          BIGINT NOT NULL UNIQUE REFERENCES controller_epochs(generation),
  previous_generation BIGINT NOT NULL REFERENCES controller_epochs(generation),
  source              TEXT NOT NULL CHECK (octet_length(source) BETWEEN 1 AND 128),
  state               TEXT NOT NULL CHECK (state IN ('reconciling','succeeded','failed')),
  total_nodes         INT NOT NULL DEFAULT 0 CHECK (total_nodes>=0),
  reconciled_nodes    INT NOT NULL DEFAULT 0 CHECK (
                        reconciled_nodes>=0 AND reconciled_nodes<=total_nodes),
  error_code          TEXT CHECK (
                        error_code IS NULL OR error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  started_at          TIMESTAMPTZ NOT NULL,
  updated_at          TIMESTAMPTZ NOT NULL,
  completed_at        TIMESTAMPTZ,
  CHECK ((state IN ('succeeded','failed'))=(completed_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS controller_rebuild_nodes (
  rebuild_id                    UUID NOT NULL REFERENCES controller_rebuild_operations(id) ON DELETE CASCADE,
  node_id                       BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  previous_credential_generation BIGINT NOT NULL CHECK (previous_credential_generation>0),
  state                         TEXT NOT NULL CHECK (state IN (
                                  'awaiting_heartbeat','heartbeat_verified',
                                  'rotation_pending','credential_activated',
                                  'draining','reconciled')),
  authenticated_generation      BIGINT CHECK (authenticated_generation>0),
  credential_version            BIGINT CHECK (credential_version>0),
  last_heartbeat_at             TIMESTAMPTZ,
  credential_activated_at       TIMESTAMPTZ,
  reconciled_at                 TIMESTAMPTZ,
  updated_at                    TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (rebuild_id,node_id)
);

CREATE INDEX IF NOT EXISTS idx_controller_rebuild_open
  ON controller_rebuild_operations (state,updated_at)
  WHERE state='reconciling';

CREATE INDEX IF NOT EXISTS idx_controller_rebuild_nodes_pending
  ON controller_rebuild_nodes (rebuild_id,state,node_id)
  WHERE state<>'reconciled';
