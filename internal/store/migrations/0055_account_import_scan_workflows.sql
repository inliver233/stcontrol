CREATE TABLE IF NOT EXISTS account_import_scan_workflows (
  operation_id          UUID PRIMARY KEY,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  created_by_admin_id   BIGINT REFERENCES admins(id) ON DELETE SET NULL,
  state                 TEXT NOT NULL DEFAULT 'queued' CHECK (state IN (
    'queued','running','retry_wait','inventory_complete','succeeded','failed','cancelled'
  )),
  controller_generation BIGINT NOT NULL CHECK (controller_generation>0),
  cursor                INT NOT NULL DEFAULT 0 CHECK (cursor>=0 AND cursor<=10000),
  total_users           INT CHECK (total_users>=0 AND total_users<=10000),
  completed_pages       INT NOT NULL DEFAULT 0 CHECK (completed_pages>=0 AND completed_pages<=200),
  inventory_revision    TEXT,
  inventory_users       JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(inventory_users)='array'),
  attempt               INT NOT NULL DEFAULT 0 CHECK (attempt>=0),
  next_attempt_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  error_code            TEXT,
  error_summary         TEXT,
  lease_owner           UUID,
  lease_until           TIMESTAMPTZ,
  batch_id              UUID REFERENCES account_import_batches(id) ON DELETE SET NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at           TIMESTAMPTZ,
  CHECK ((lease_owner IS NULL)=(lease_until IS NULL)),
  CHECK (inventory_revision IS NULL OR inventory_revision ~ '^[0-9a-f]{64}$'),
  CHECK ((state IN ('succeeded','failed','cancelled'))=(finished_at IS NOT NULL)),
  CHECK ((state='succeeded')=(batch_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_account_import_scan_due
  ON account_import_scan_workflows (next_attempt_at,created_at)
  WHERE state IN ('queued','running','retry_wait','inventory_complete');

CREATE INDEX IF NOT EXISTS idx_account_import_scan_node
  ON account_import_scan_workflows (node_id,created_at DESC);

-- Conflict evidence must address the source node's actual local account. One
-- Discord identity may legitimately have different handles on independently
-- operated nodes before they join the Controller.
ALTER TABLE replica_conflict_sources ADD COLUMN IF NOT EXISTS local_handle TEXT;
ALTER TABLE replica_conflict_sources ADD CONSTRAINT ck_replica_conflict_source_local_handle
  CHECK (local_handle IS NULL OR (octet_length(local_handle)>0 AND octet_length(local_handle)<=128));
