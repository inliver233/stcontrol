ALTER TABLE node_accounts
  ADD COLUMN IF NOT EXISTS provisioning_workflow_id UUID REFERENCES workflows(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_node_accounts_provisioning_workflow
  ON node_accounts (provisioning_workflow_id) WHERE provisioning_workflow_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS restore_operations (
  id                       BIGSERIAL PRIMARY KEY,
  operation_id             UUID NOT NULL UNIQUE,
  request_digest           BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
  workflow_id              UUID NOT NULL UNIQUE REFERENCES workflows(id) ON DELETE RESTRICT,
  user_id                  BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  source_node_id           BIGINT NOT NULL REFERENCES nodes(id),
  target_node_id           BIGINT NOT NULL REFERENCES nodes(id),
  source_snapshot_id       UUID NOT NULL REFERENCES snapshot_manifests(id) ON DELETE RESTRICT,
  restore_snapshot_id      UUID NOT NULL UNIQUE REFERENCES snapshot_manifests(id) ON DELETE RESTRICT,
  source_published_at      TIMESTAMPTZ NOT NULL,
  acknowledged_at          TIMESTAMPTZ NOT NULL,
  completed_at             TIMESTAMPTZ,
  CHECK (source_node_id<>target_node_id)
);
CREATE INDEX IF NOT EXISTS idx_restore_operations_user
  ON restore_operations (user_id,id DESC);
