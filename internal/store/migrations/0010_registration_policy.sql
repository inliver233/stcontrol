ALTER TABLE nodes
  ADD COLUMN IF NOT EXISTS registration_policy_observed_at TIMESTAMPTZ;
ALTER TABLE nodes
  ADD COLUMN IF NOT EXISTS registration_policy_error_code TEXT;

ALTER TABLE nodes DROP CONSTRAINT IF EXISTS nodes_registration_policy_state_check;
ALTER TABLE nodes
  ADD CONSTRAINT nodes_registration_policy_state_check
  CHECK (registration_policy_state IN ('unknown','open','invitation_required','closed','error'));

-- Existing nodes have never reported an authoritative node-owned policy.
-- Keep them fail-closed until their Agent successfully reads the adapter.
UPDATE nodes
SET registration_policy_state='unknown', registration_policy_version=0,
    registration_policy_expires_at=NULL, registration_policy_observed_at=NULL,
    registration_policy_error_code=NULL;
