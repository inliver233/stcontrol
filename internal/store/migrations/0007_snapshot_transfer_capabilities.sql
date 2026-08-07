ALTER TABLE nodes ADD COLUMN IF NOT EXISTS transfer_url TEXT NOT NULL DEFAULT '';
UPDATE nodes SET agent_url='', agent_psk='';
ALTER TABLE nodes DROP COLUMN IF EXISTS agent_url;
ALTER TABLE nodes DROP COLUMN IF EXISTS agent_psk;

ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS workflow_id UUID REFERENCES workflows(id);
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS snapshot_id UUID REFERENCES snapshot_manifests(id);
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS activity_epoch BIGINT;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS resume_state TEXT;

CREATE TABLE IF NOT EXISTS snapshot_transfer_capabilities (
  id                    UUID PRIMARY KEY,
  workflow_id           UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
  snapshot_id           UUID NOT NULL REFERENCES snapshot_manifests(id) ON DELETE CASCADE,
  source_node_id        BIGINT NOT NULL REFERENCES nodes(id),
  target_node_id        BIGINT NOT NULL REFERENCES nodes(id),
  token_hash            BYTEA NOT NULL UNIQUE,
  state                 TEXT NOT NULL CHECK (state IN ('prepared','consumed','revoked','expired')),
  controller_generation BIGINT NOT NULL CHECK (controller_generation > 0),
  expires_at            TIMESTAMPTZ NOT NULL,
  consumed_at           TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_snapshot_transfer_capabilities_expiry
  ON snapshot_transfer_capabilities (expires_at) WHERE state='prepared';
CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshot_transfer_one_prepared
  ON snapshot_transfer_capabilities (workflow_id) WHERE state='prepared';
