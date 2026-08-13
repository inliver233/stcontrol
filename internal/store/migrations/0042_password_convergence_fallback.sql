-- 0042: password-sync convergence fallback + node-level password removal intents
-- (R14 unified identity; see internal/store/users.go, identities.go and the
-- controller password-sync worker).

-- Keep one immediately-previous control-plane password hash as a bounded,
-- time-limited fallback while the password-sync saga is incomplete. Login only
-- accepts the previous verifier while some node account still holds the prior
-- material (status pending/error) AND the change is younger than the configured
-- window; after every node converges the fallback is dropped. The column stays
-- NULL on first bind so a fresh identity never enables a stale fallback.
ALTER TABLE auth_identities
  ADD COLUMN IF NOT EXISTS previous_password_hash TEXT,
  ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;

-- Unbinding the password identity must revoke the password on every node that
-- carries a local (tavern) account, including nodes that were offline at unbind
-- time. These durable intents are driven by the password-sync worker: it pushes
-- a remove-password command to each reachable node and only clears the intent
-- when that node confirms. Rows are retried (bounded by updated_at backoff)
-- until the node converges.
CREATE TABLE IF NOT EXISTS node_account_password_removals (
  id                        BIGSERIAL PRIMARY KEY,
  global_user_id            BIGINT NOT NULL REFERENCES global_users(id) ON DELETE CASCADE,
  node_id                   BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  local_handle              TEXT NOT NULL,
  state                     TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','completed')),
  attempt                   INT NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (global_user_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_node_account_password_removals_pending
  ON node_account_password_removals (state, updated_at) WHERE state='pending';
