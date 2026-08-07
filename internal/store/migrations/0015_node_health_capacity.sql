ALTER TABLE nodes ADD COLUMN IF NOT EXISTS disk_total_bytes BIGINT CHECK (disk_total_bytes>=0);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS disk_quota_bytes BIGINT CHECK (disk_quota_bytes>=0);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS metrics_observed_at TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS telemetry_source TEXT NOT NULL DEFAULT 'unavailable';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS cpu_window_avg REAL CHECK (cpu_window_avg BETWEEN 0 AND 100);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS cpu_window_peak REAL CHECK (cpu_window_peak BETWEEN 0 AND 100);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS mem_window_avg REAL CHECK (mem_window_avg BETWEEN 0 AND 100);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS mem_window_peak REAL CHECK (mem_window_peak BETWEEN 0 AND 100);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS disk_window_avg REAL CHECK (disk_window_avg BETWEEN 0 AND 100);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS disk_window_peak REAL CHECK (disk_window_peak BETWEEN 0 AND 100);
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS capacity_state TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS capacity_reason_code TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS capacity_pressure_since TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS capacity_recovery_since TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS capacity_changed_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS capacity_cooldown_until TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS compatibility_state TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS compatibility_reason_code TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS compatibility_reported_at TIMESTAMPTZ;

UPDATE nodes SET
  connectivity_state=CASE status WHEN 'online' THEN 'online' WHEN 'offline' THEN 'offline' ELSE 'unknown' END,
  operational_state=CASE WHEN status='pending' THEN 'pending' ELSE 'active' END,
  capacity_state='unknown',
  compatibility_state='unknown';

UPDATE nodes SET disk_available_bytes=NULL WHERE disk_available_bytes<0;
UPDATE nodes SET allocated_disk_bytes=NULL WHERE allocated_disk_bytes<0;
UPDATE nodes SET online_users=0 WHERE online_users<0;
UPDATE nodes SET task_queue_depth=0 WHERE task_queue_depth<0;

ALTER TABLE nodes ADD CONSTRAINT nodes_connectivity_state_check
  CHECK (connectivity_state IN ('unknown','online','offline'));
ALTER TABLE nodes ADD CONSTRAINT nodes_operational_state_check
  CHECK (operational_state IN ('pending','active','maintenance','draining','degraded','failed','retired'));
ALTER TABLE nodes ADD CONSTRAINT nodes_capacity_state_check
  CHECK (capacity_state IN ('unknown','open','busy','full'));
ALTER TABLE nodes ADD CONSTRAINT nodes_compatibility_state_check
  CHECK (compatibility_state IN ('unknown','compatible','incompatible'));
ALTER TABLE nodes ADD CONSTRAINT nodes_telemetry_source_check
  CHECK (telemetry_source IN ('adapter','directory_fallback','agent','unavailable'));
ALTER TABLE nodes ADD CONSTRAINT nodes_disk_available_nonnegative_check
  CHECK (disk_available_bytes IS NULL OR disk_available_bytes>=0);
ALTER TABLE nodes ADD CONSTRAINT nodes_allocated_disk_nonnegative_check
  CHECK (allocated_disk_bytes IS NULL OR allocated_disk_bytes>=0);
ALTER TABLE nodes ADD CONSTRAINT nodes_disk_capacity_consistent_check
  CHECK (disk_total_bytes IS NULL OR disk_available_bytes IS NULL OR disk_available_bytes<=disk_total_bytes);
ALTER TABLE nodes ADD CONSTRAINT nodes_disk_quota_consistent_check
  CHECK (disk_total_bytes IS NULL OR disk_quota_bytes IS NULL OR disk_quota_bytes<=disk_total_bytes);
ALTER TABLE nodes ADD CONSTRAINT nodes_online_users_nonnegative_check CHECK (online_users>=0);
ALTER TABLE nodes ADD CONSTRAINT nodes_task_queue_nonnegative_check CHECK (task_queue_depth>=0);

CREATE INDEX IF NOT EXISTS idx_nodes_allocation_health
  ON nodes (role,connectivity_state,operational_state,compatibility_state,capacity_state,id);
CREATE INDEX IF NOT EXISTS idx_node_metric_samples_retention
  ON node_metric_samples (sampled_at);
