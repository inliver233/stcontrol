-- R18: persist client-measured latency so node selection can use it after
-- page reloads instead of only the current tab.  The controller keeps a
-- simple EWMA-style latest value plus the observation time; no per-user
-- history is retained (privacy: latency is not identity data).
ALTER TABLE nodes
  ADD COLUMN IF NOT EXISTS client_latency_ms INT CHECK (client_latency_ms IS NULL OR client_latency_ms >= 0),
  ADD COLUMN IF NOT EXISTS client_latency_observed_at TIMESTAMPTZ;
