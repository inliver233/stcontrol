-- 0049: bind password-removal intents to immutable password material versions.
-- Older delayed remove-password deliveries must never clear a newer password
-- that was rebound or rotated after the original unbind.

ALTER TABLE node_account_password_removals
  ADD COLUMN IF NOT EXISTS password_material_version BIGINT NOT NULL DEFAULT 0;

-- A pre-0049 intent is safe to carry forward only when the current node
-- account still represents the password-less state created by that unbind.
-- If newer material is already present, completing the legacy intent prevents
-- a delayed delivery from deleting the newer password.
UPDATE node_account_password_removals removal
SET password_material_version=account.password_material_version
FROM node_accounts account
WHERE account.user_id=removal.global_user_id
  AND account.node_id=removal.node_id
  AND account.password_hash IS NULL
  AND account.password_salt IS NULL
  AND account.password_material_version>0
  AND removal.password_material_version=0
  AND removal.state='pending';

UPDATE node_account_password_removals removal
SET state='completed',updated_at=now()
WHERE removal.password_material_version=0
  AND removal.state='pending'
  AND NOT EXISTS (
    SELECT 1 FROM node_accounts account
    WHERE account.user_id=removal.global_user_id
      AND account.node_id=removal.node_id
      AND account.password_hash IS NULL
      AND account.password_salt IS NULL
      AND account.password_material_version>0
  );

ALTER TABLE node_account_password_removals
  ADD CONSTRAINT node_account_password_removals_password_material_version_nonnegative
  CHECK (password_material_version >= 0);
