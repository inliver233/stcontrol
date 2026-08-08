ALTER TABLE admin_node_links ADD COLUMN IF NOT EXISTS local_user_id TEXT;
ALTER TABLE admin_node_links ADD COLUMN IF NOT EXISTS permission_version BIGINT;
ALTER TABLE admin_node_links ADD COLUMN IF NOT EXISTS last_error_code TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_node_links_local_identity
  ON admin_node_links (node_id,local_user_id)
  WHERE state='verified' AND local_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS admin_node_link_operations (
  operation_id          UUID PRIMARY KEY,
  request_digest        BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
  admin_id              BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  node_id               BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  local_handle          TEXT NOT NULL,
  outcome               TEXT NOT NULL CHECK (outcome IN ('verified','rejected')),
  result_local_user_id  TEXT,
  permission_version    BIGINT,
  error_code            TEXT,
  controller_generation BIGINT NOT NULL CHECK (controller_generation>0),
  completed_at          TIMESTAMPTZ NOT NULL,
  CHECK ((outcome='verified')=(result_local_user_id IS NOT NULL)),
  CHECK ((outcome='verified')=(permission_version IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_admin_node_link_operations_admin
  ON admin_node_link_operations (admin_id,node_id,completed_at DESC);

ALTER TABLE control_tickets ADD COLUMN IF NOT EXISTS admin_id BIGINT REFERENCES admins(id) ON DELETE CASCADE;
DELETE FROM control_tickets WHERE ticket_type='node_admin' AND admin_id IS NULL;
ALTER TABLE control_tickets ADD CONSTRAINT ck_control_tickets_principal
  CHECK (
    (ticket_type='node_admin' AND admin_id IS NOT NULL AND user_id IS NULL)
    OR (ticket_type<>'node_admin' AND admin_id IS NULL)
  );
